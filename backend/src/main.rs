//! Z-Scanner API — Actix-web application serving the scanning endpoints and static frontend.
//!
//! Drop-in replacement for the Python FastAPI backend. All API endpoints, request/response
//! shapes, and behavior are identical. The frontend works without any changes.

mod models;
mod owasp;
mod scanner;

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use actix_cors::Cors;
use actix_files::Files;
use actix_web::web::Query;
use actix_web::{web, App, HttpResponse, HttpServer};
use tokio::sync::RwLock;
use tracing::info;

use models::*;
use scanner::ZapScanner;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Thread-safe scan store shared across all handlers and background tasks.
struct AppState {
    scans: RwLock<HashMap<String, Arc<ScanStatus>>>,
    scanner: ZapScanner,
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "Z-Scanner API"
    }))
}

async fn start_scan(
    data: web::Data<AppState>,
    body: web::Json<ScanRequest>,
) -> HttpResponse {
    let scan_id = uuid::Uuid::new_v4().to_string()[..12].to_string();

    // Normalize the target URL: rewrite localhost/127.0.0.1 → host.docker.internal
    // so ZAP running inside Docker can reach services on the host machine.
    let target = normalize_target_url(&body.target_url);

    // Basic validation: must start with http:// or https://
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "detail": "Invalid URL — must start with http:// or https://"
        }));
    }

    // Validate scan mode
    let scan_mode = match body.scan_mode.as_str() {
        "quick" | "fast" | "deep" | "stealth" => body.scan_mode.clone(),
        _ => "fast".to_string(),
    };

    // Prevent duplicate concurrent scans
    {
        let scans = data.scans.read().await;
        for existing in scans.values() {
            if existing.target_url == target && !existing.get_phase().is_terminal() {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "detail": format!(
                        "A scan for {} is already running (scan_id={})",
                        target, existing.scan_id
                    )
                }));
            }
        }
    }

    let status = Arc::new(ScanStatus::new(
        scan_id.clone(),
        target.clone(),
        scan_mode.clone(),
    ));

    info!(scan_mode = %scan_mode, "Scan mode selected");

    // Store scan
    {
        let mut scans = data.scans.write().await;
        scans.insert(scan_id.clone(), Arc::clone(&status));
    }

    // Spawn background scan task
    let scanner = data.scanner.clone();
    let mode_cfg = get_scan_mode_config(&scan_mode);
    let status_clone = Arc::clone(&status);
    tokio::spawn(async move {
        scanner.run_full_scan(status_clone, mode_cfg).await;
    });

    info!(scan_id = %scan_id, target = %target, "Scan queued");

    HttpResponse::Ok().json(ScanResponse {
        scan_id,
        message: "Scan started successfully".to_string(),
    })
}

async fn get_status(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let scans = data.scans.read().await;

    match scans.get(&scan_id) {
        Some(status) => HttpResponse::Ok().json(StatusResponse {
            scan_id: status.scan_id.clone(),
            target_url: status.target_url.clone(),
            phase: status.get_phase().as_str().to_string(),
            spider_progress: status.get_spider_progress(),
            active_scan_progress: status.get_active_scan_progress(),
            error: status.get_error(),
        }),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "detail": "Scan not found"
        })),
    }
}

async fn stop_scan(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let scans = data.scans.read().await;

    match scans.get(&scan_id) {
        Some(status) => {
            if status.get_phase().is_terminal() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "detail": "Scan is not running"
                }));
            }
            data.scanner.force_stop(status).await;
            info!(scan_id = %scan_id, "Force stop executed");
            HttpResponse::Ok().json(serde_json::json!({
                "scan_id": scan_id,
                "message": "Scan stopped"
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({
            "detail": "Scan not found"
        })),
    }
}

async fn get_results(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let scans = data.scans.read().await;

    match scans.get(&scan_id) {
        Some(status) => {
            let alerts = status.get_alerts();
            let summary = AlertSummary::from_alerts(&alerts);
            HttpResponse::Ok().json(ResultsResponse {
                scan_id: status.scan_id.clone(),
                target_url: status.target_url.clone(),
                phase: status.get_phase().as_str().to_string(),
                total_alerts: alerts.len(),
                summary,
                alerts,
            })
        }
        None => HttpResponse::NotFound().json(serde_json::json!({
            "detail": "Scan not found"
        })),
    }
}

async fn get_history(data: web::Data<AppState>) -> HttpResponse {
    let scans = data.scans.read().await;
    let mut entries: Vec<HistoryEntry> = scans
        .values()
        .map(|s| {
            let alerts = s.get_alerts();
            let summary = AlertSummary::from_alerts(&alerts);
            HistoryEntry {
                scan_id: s.scan_id.clone(),
                target_url: s.target_url.clone(),
                scan_mode: s.scan_mode.clone(),
                phase: s.get_phase().as_str().to_string(),
                started_at: s.started_at,
                finished_at: s.get_finished_at(),
                alert_summary: summary,
                total_alerts: alerts.len(),
            }
        })
        .collect();

    // Newest first
    entries.sort_by(|a, b| b.started_at.partial_cmp(&a.started_at).unwrap());
    HttpResponse::Ok().json(entries)
}

async fn export_scan(
    data: web::Data<AppState>,
    path: web::Path<String>,
    query: Query<ExportQuery>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let scans = data.scans.read().await;

    let status = match scans.get(&scan_id) {
        Some(s) => s,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "detail": "Scan not found"
            }))
        }
    };

    let alerts = status.get_alerts();

    if query.format == "csv" {
        let mut wtr = csv::Writer::from_writer(Vec::new());

        // Write header
        let _ = wtr.write_record([
            "id", "name", "risk", "confidence", "description", "url",
            "affected_urls", "solution", "reference", "cweid", "cwe_link", "wascid",
            "param", "evidence", "owasp_code", "owasp_category",
        ]);

        for alert in &alerts {
            let affected = alert.affected_urls.join("; ");
            let _ = wtr.write_record([
                &alert.id,
                &alert.name,
                &alert.risk,
                &alert.confidence,
                &alert.description,
                &alert.url,
                &affected,
                &alert.solution,
                &alert.reference,
                &alert.cweid,
                &alert.cwe_link,
                &alert.wascid,
                &alert.param,
                &alert.evidence,
                &alert.owasp_code,
                &alert.owasp_category,
            ]);
        }

        let csv_bytes = wtr.into_inner().unwrap_or_default();
        return HttpResponse::Ok()
            .content_type("text/csv")
            .insert_header((
                "Content-Disposition",
                format!("attachment; filename=\"zscan-{}.csv\"", scan_id),
            ))
            .body(csv_bytes);
    }

    // Default: JSON
    let summary = AlertSummary::from_alerts(&alerts);
    HttpResponse::Ok().json(ExportJson {
        scan_id: status.scan_id.clone(),
        target_url: status.target_url.clone(),
        scan_mode: status.scan_mode.clone(),
        phase: status.get_phase().as_str().to_string(),
        started_at: status.started_at,
        finished_at: status.get_finished_at(),
        summary,
        total_alerts: alerts.len(),
        alerts,
    })
}

/// Serve the frontend index.html
async fn serve_index() -> actix_web::Result<actix_files::NamedFile> {
    let frontend_dir = get_frontend_dir();
    let index = std::path::PathBuf::from(&frontend_dir).join("index.html");
    Ok(actix_files::NamedFile::open(index)?)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Rewrite `localhost`, `127.0.0.1`, and `0.0.0.0` in target URLs to
/// `host.docker.internal` so that ZAP running inside Docker can reach
/// services on the host machine.
///
/// Examples:
///   http://localhost:3000      → http://host.docker.internal:3000
///   https://127.0.0.1:8443    → https://host.docker.internal:8443
///   http://192.168.1.50:8080  → unchanged (LAN IPs work directly)
fn normalize_target_url(raw: &str) -> String {
    let mut url = raw.trim().to_string();

    // Replace localhost variants with host.docker.internal
    // This allows users to type "localhost" naturally while ZAP can
    // actually reach the host from inside its container.
    let patterns = [
        "://localhost:", "://localhost/", "://localhost",
        "://127.0.0.1:", "://127.0.0.1/", "://127.0.0.1",
        "://0.0.0.0:", "://0.0.0.0/", "://0.0.0.0",
    ];

    for pattern in &patterns {
        if let Some(pos) = url.find(pattern) {
            let prefix_end = pos + 3; // after "://"
            let host_start = prefix_end;
            // Find where the host part ends (before : or / or end of string)
            let old_host = if pattern.contains("localhost") {
                "localhost"
            } else if pattern.contains("127.0.0.1") {
                "127.0.0.1"
            } else {
                "0.0.0.0"
            };
            url = format!(
                "{}host.docker.internal{}",
                &url[..host_start],
                &url[host_start + old_host.len()..]
            );
            info!(
                original = raw,
                rewritten = %url,
                "Rewrote localhost target → host.docker.internal"
            );
            break;
        }
    }

    url
}

fn get_frontend_dir() -> String {
    // Try ../frontend first (Docker volume mount), then ./frontend
    let candidate = std::path::Path::new("../frontend");
    if candidate.is_dir() {
        return candidate.to_string_lossy().to_string();
    }
    let candidate2 = std::path::Path::new("./frontend");
    if candidate2.is_dir() {
        return candidate2.to_string_lossy().to_string();
    }
    // Fallback
    "../frontend".to_string()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zscanner=debug".parse().unwrap()),
        )
        .with_target(true)
        .init();

    let zap_url = env::var("ZAP_API_URL").unwrap_or_else(|_| "http://zap:8080".to_string());
    info!(zap_url = %zap_url, "Z-Scanner API starting");

    let state = web::Data::new(AppState {
        scans: RwLock::new(HashMap::new()),
        scanner: ZapScanner::new(&zap_url),
    });

    let frontend_dir = get_frontend_dir();
    info!(frontend_dir = %frontend_dir, "Serving frontend from");

    HttpServer::new(move || {
        let cors = Cors::permissive();

        let mut app = App::new()
            .wrap(cors)
            .app_data(state.clone())
            // API routes
            .route("/api/health", web::get().to(health_check))
            .route("/api/scan", web::post().to(start_scan))
            .route("/api/status/{scan_id}", web::get().to(get_status))
            .route("/api/stop/{scan_id}", web::post().to(stop_scan))
            .route("/api/results/{scan_id}", web::get().to(get_results))
            .route("/api/history", web::get().to(get_history))
            .route("/api/export/{scan_id}", web::get().to(export_scan))
            // Serve index.html at root
            .route("/", web::get().to(serve_index));

        // Mount static files (CSS, JS) — must come after explicit routes
        let fe = get_frontend_dir();
        if std::path::Path::new(&fe).is_dir() {
            app = app.service(Files::new("/", &fe).prefer_utf8(true));
        }

        app
    })
    .bind("0.0.0.0:8000")?
    .run()
    .await
}
