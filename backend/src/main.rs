//! BlackHawk API — Actix-web application serving the scanning endpoints and static frontend.
//!
//! Drop-in replacement for the Python FastAPI backend. All API endpoints, request/response
//! shapes, and behavior are identical. The frontend works without any changes.

mod db;
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
use tracing::warn;

use models::{AlertData, AlertSummary, ScannerConfig, ScanStatus, *};
use scanner::ZapScanner;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Thread-safe scan store shared across all handlers and background tasks.
struct AppState {
    scans: RwLock<HashMap<String, Arc<ScanStatus>>>,
    scanner: ZapScanner,
    config: ScannerConfig,
    max_concurrent_scans: usize,
    active_scan_enabled: bool,
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "BlackHawk API"
    }))
}

async fn start_scan(req: actix_web::HttpRequest, data: web::Data<AppState>, body: web::Json<ScanRequest>) -> HttpResponse {
    // Check API key if configured
    if !check_api_key(&req, &data.config) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "detail": "Invalid or missing API key"
        }));
    }

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
        _ => "stealth".to_string(),
    };

    // Prevent accidental load against one or many targets.
    {
        let scans = data.scans.read().await;
        let running_count = scans
            .values()
            .filter(|existing| !existing.get_phase().is_terminal())
            .count();
        if running_count >= data.max_concurrent_scans {
            return HttpResponse::TooManyRequests().json(serde_json::json!({
                "detail": format!(
                    "Scanner is at the configured concurrency limit ({} running)",
                    data.max_concurrent_scans
                )
            }));
        }

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
    let config = data.config.clone();
    let mut mode_cfg = get_scan_mode_config(&scan_mode, &config);
    if mode_cfg.run_active_scan && !data.active_scan_enabled {
        info!(
            scan_id = %scan_id,
            requested_mode = %scan_mode,
            "Active scan requested but disabled; running passive spider-only scan"
        );
        mode_cfg.run_active_scan = false;
    }
    let task_config = config.clone();
    let status_clone = Arc::clone(&status);
    let db_path = config.db_path.clone();
    let webhook_url = config.webhook_url.clone();
    let scan_id_clone = scan_id.clone();
    let target_clone = target.clone();
    let scan_mode_clone = scan_mode.clone();
    tokio::spawn(async move {
        scanner.run_full_scan(status_clone, mode_cfg, &task_config).await;
        // Persist to database after completion
        let phase = status.get_phase().as_str().to_string();
        let alerts = status.get_alerts();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            let _ = db::update_scan_result(&conn, &status.scan_id, &phase, &alerts);
        }
        // Fire webhook notification if configured
        if let Some(url) = webhook_url {
            if phase == "complete" || phase == "stopped" {
                let wh_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap_or_default();
                send_webhook(
                    &wh_client,
                    &url,
                    &scan_id_clone,
                    &target_clone,
                    &scan_mode_clone,
                    &phase,
                    &alerts,
                ).await;
            }
        }
    });

    // Save scan start to DB
    {
        if let Ok(conn) = rusqlite::Connection::open(&config.db_path) {
            let _ = db::save_scan(&conn, &scan_id, &target, &scan_mode);
        }
    }

    info!(scan_id = %scan_id, target = %target, "Scan queued");

    HttpResponse::Ok().json(ScanResponse {
        scan_id,
        message: "Scan started successfully".to_string(),
    })
}

async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
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

async fn stop_scan(req: actix_web::HttpRequest, data: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if !check_api_key(&req, &data.config) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "detail": "Invalid or missing API key"
        }));
    }
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

async fn get_results(data: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let scan_id = path.into_inner();
    let scans = data.scans.read().await;

    if let Some(status) = scans.get(&scan_id) {
        let alerts = status.get_alerts();
        let summary = AlertSummary::from_alerts(&alerts);
        return HttpResponse::Ok().json(ResultsResponse {
            scan_id: status.scan_id.clone(),
            target_url: status.target_url.clone(),
            phase: status.get_phase().as_str().to_string(),
            total_alerts: alerts.len(),
            summary,
            alerts,
        });
    }

    // Fall back to database for persisted scans
    if let Ok(conn) = rusqlite::Connection::open(&data.config.db_path) {
        if let Some((entry, alerts)) = db::load_scan_results(&conn, &scan_id) {
            return HttpResponse::Ok().json(ResultsResponse {
                scan_id: entry.scan_id,
                target_url: entry.target_url,
                phase: entry.phase,
                total_alerts: entry.total_alerts,
                summary: entry.alert_summary,
                alerts,
            });
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "detail": "Scan not found"
    }))
}

async fn get_history(data: web::Data<AppState>) -> HttpResponse {
    let scans = data.scans.read().await;
    let mut in_memory_ids = std::collections::HashSet::new();
    let mut entries: Vec<HistoryEntry> = scans
        .values()
        .map(|s| {
            in_memory_ids.insert(s.scan_id.clone());
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

    // Merge from database for persisted scans not in memory
    if let Ok(conn) = rusqlite::Connection::open(&data.config.db_path) {
        for entry in db::load_history(&conn) {
            if !in_memory_ids.contains(&entry.scan_id) {
                entries.push(entry);
            }
        }
    }

    // Newest first
    entries.sort_by(|a, b| {
        b.started_at
            .partial_cmp(&a.started_at)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
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
            "id",
            "name",
            "risk",
            "confidence",
            "description",
            "url",
            "affected_urls",
            "solution",
            "reference",
            "cweid",
            "cwe_link",
            "wascid",
            "param",
            "evidence",
            "owasp_code",
            "owasp_category",
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
    let trimmed = raw.trim().to_string();
    // Work on a lowercase copy for case-insensitive matching,
    // but preserve the original casing for the rest of the URL.
    let lower = trimmed.to_ascii_lowercase();
    // This allows users to type "localhost" naturally while ZAP can
    // actually reach the host from inside its container.
    let patterns = [
        ("://localhost:", "localhost"),
        ("://localhost/", "localhost"),
        ("://localhost", "localhost"),
        ("://127.0.0.1:", "127.0.0.1"),
        ("://127.0.0.1/", "127.0.0.1"),
        ("://127.0.0.1", "127.0.0.1"),
        ("://0.0.0.0:", "0.0.0.0"),
        ("://0.0.0.0/", "0.0.0.0"),
        ("://0.0.0.0", "0.0.0.0"),
    ];

    for (pattern, old_host) in &patterns {
        if let Some(pos) = lower.find(pattern) {
            let prefix_end = pos + 3; // after "://"
            let host_start = prefix_end;
            let mut url = trimmed.clone();
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
            return url;
        }
    }

    trimmed
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
                .unwrap_or_else(|_| "info,blackhawk=debug".parse().unwrap()),
        )
        .with_target(true)
        .init();

    let zap_url = env::var("ZAP_API_URL").unwrap_or_else(|_| "http://zap:8080".to_string());
    let active_scan_enabled = env_bool("ZSCANNER_ENABLE_ACTIVE_SCAN", false);
    let max_concurrent_scans = env::var("ZSCANNER_MAX_CONCURRENT_SCANS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1);

    // Parse extended configuration from env vars
    let config = ScannerConfig {
        alert_threshold: env::var("ZSCANNER_ALERT_THRESHOLD")
            .unwrap_or_else(|_| "MEDIUM".to_string()),
        min_confidence_rank: env::var("ZSCANNER_MIN_CONFIDENCE")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|v| *v <= 3)
            .unwrap_or(2),
        excluded_alerts: env::var("ZSCANNER_EXCLUDED_ALERTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        alert_fetch_count: env::var("ZSCANNER_ALERT_FETCH_COUNT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(5000),
        api_key: env::var("ZSCANNER_API_KEY").ok().filter(|k| !k.is_empty()),
        webhook_url: env::var("ZSCANNER_WEBHOOK_URL")
            .ok()
            .filter(|u| !u.is_empty()),
        db_path: env::var("ZSCANNER_DB_PATH")
            .unwrap_or_else(|_| "data/scans.db".to_string()),
        spider_threads_quick: env::var("ZSCANNER_SPIDER_THREADS_QUICK")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(2),
        spider_threads_fast: env::var("ZSCANNER_SPIDER_THREADS_FAST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(4),
        spider_threads_deep: env::var("ZSCANNER_SPIDER_THREADS_DEEP")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(6),
        spider_delay_quick: env::var("ZSCANNER_SPIDER_DELAY_QUICK")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(300),
        spider_delay_fast: env::var("ZSCANNER_SPIDER_DELAY_FAST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(200),
        spider_delay_deep: env::var("ZSCANNER_SPIDER_DELAY_DEEP")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(100),
    };

    // Initialize database
    db::ensure_db_dir(&config.db_path);
    if let Ok(conn) = rusqlite::Connection::open(&config.db_path) {
        if db::init_db(&conn).is_ok() {
            info!("Database initialized at {}", config.db_path);
        } else {
            warn!("Failed to initialize database — scans will not be persisted");
        }
    } else {
        warn!("Failed to open database — scans will not be persisted");
    }

    info!(zap_url = %zap_url, "BlackHawk API starting");
    info!(
        active_scan_enabled = active_scan_enabled,
        max_concurrent_scans = max_concurrent_scans,
        alert_threshold = %config.alert_threshold,
        min_confidence = config.min_confidence_rank,
        excluded_alerts = ?config.excluded_alerts,
        api_key_configured = config.api_key.is_some(),
        webhook_url_configured = config.webhook_url.is_some(),
        "Scanner configuration loaded"
    );

    let state = web::Data::new(AppState {
        scans: RwLock::new(HashMap::new()),
        scanner: ZapScanner::new(&zap_url),
        config,
        max_concurrent_scans,
        active_scan_enabled,
    });

    let frontend_dir = get_frontend_dir();
    info!(frontend_dir = %frontend_dir, "Serving frontend from");

    HttpServer::new(move || {
        let cors = Cors::permissive();

        let mut app = App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::new(
                "%a \"%r\" %s %b %Dms"
            ))
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

/// Send a webhook notification when a scan completes.
async fn send_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    scan_id: &str,
    target_url: &str,
    scan_mode: &str,
    phase: &str,
    alerts: &[AlertData],
) {
    let summary = AlertSummary::from_alerts(alerts);
    let payload = serde_json::json!({
        "event": "scan_complete",
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "phase": phase,
        "summary": {
            "High": summary.high,
            "Medium": summary.medium,
            "Low": summary.low,
        },
        "total_alerts": alerts.len(),
    });

    match client.post(webhook_url).json(&payload).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                info!(scan_id = %scan_id, webhook = %webhook_url, "Webhook sent successfully");
            } else {
                warn!(
                    scan_id = %scan_id,
                    status = %resp.status(),
                    "Webhook returned non-success status"
                );
            }
        }
        Err(e) => {
            warn!(scan_id = %scan_id, error = %e, "Failed to send webhook");
        }
    }
}

/// Check if the request has a valid API key (if one is configured).
fn check_api_key(req: &actix_web::HttpRequest, config: &ScannerConfig) -> bool {
    match &config.api_key {
        None => true, // API key auth disabled
        Some(key) => {
            req.headers()
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                == Some(key.as_str())
        }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // normalize_target_url
    // ---------------------------------------------------------------
    #[test]
    fn rewrite_localhost_with_port() {
        assert_eq!(
            normalize_target_url("http://localhost:3000"),
            "http://host.docker.internal:3000"
        );
    }

    #[test]
    fn rewrite_localhost_no_port() {
        assert_eq!(
            normalize_target_url("http://localhost"),
            "http://host.docker.internal"
        );
    }

    #[test]
    fn rewrite_localhost_with_path() {
        assert_eq!(
            normalize_target_url("http://localhost/api/test"),
            "http://host.docker.internal/api/test"
        );
    }

    #[test]
    fn rewrite_127_0_0_1_with_port() {
        assert_eq!(
            normalize_target_url("https://127.0.0.1:8443"),
            "https://host.docker.internal:8443"
        );
    }

    #[test]
    fn rewrite_127_0_0_1_no_port() {
        assert_eq!(
            normalize_target_url("http://127.0.0.1"),
            "http://host.docker.internal"
        );
    }

    #[test]
    fn rewrite_0_0_0_0() {
        assert_eq!(
            normalize_target_url("http://0.0.0.0:8080"),
            "http://host.docker.internal:8080"
        );
    }

    #[test]
    fn preserve_lan_ip() {
        let url = "http://192.168.1.50:3000";
        assert_eq!(normalize_target_url(url), url);
    }

    #[test]
    fn preserve_external_domain() {
        let url = "https://example.com";
        assert_eq!(normalize_target_url(url), url);
    }

    #[test]
    fn case_insensitive_localhost() {
        assert_eq!(
            normalize_target_url("http://LOCALHOST:5000"),
            "http://host.docker.internal:5000"
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            normalize_target_url("  http://localhost:3000  "),
            "http://host.docker.internal:3000"
        );
    }

    #[test]
    fn preserves_host_docker_internal() {
        let url = "http://host.docker.internal:3000";
        assert_eq!(normalize_target_url(url), url);
    }

    #[test]
    fn rewrite_localhost_with_https() {
        assert_eq!(
            normalize_target_url("https://localhost:8443/admin"),
            "https://host.docker.internal:8443/admin"
        );
    }

    #[test]
    fn rewrite_127_0_0_1_with_path_and_port() {
        assert_eq!(
            normalize_target_url("http://127.0.0.1:8080/api/v1/test"),
            "http://host.docker.internal:8080/api/v1/test"
        );
    }

    #[test]
    fn rewrite_0_0_0_0_no_port() {
        assert_eq!(
            normalize_target_url("http://0.0.0.0"),
            "http://host.docker.internal"
        );
    }

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(normalize_target_url(""), "");
    }

    #[test]
    fn no_protocol_unchanged() {
        assert_eq!(
            normalize_target_url("localhost:3000"),
            "localhost:3000"
        );
    }

    #[test]
    fn ten_dot_network_unchanged() {
        let url = "http://10.0.0.5:8080";
        assert_eq!(normalize_target_url(url), url);
    }

    #[test]
    fn mixed_case_localhost_with_port() {
        assert_eq!(
            normalize_target_url("HTTP://LOCALHOST:3000"),
            "HTTP://host.docker.internal:3000"
        );
    }
}
