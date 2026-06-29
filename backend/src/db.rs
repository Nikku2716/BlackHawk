use rusqlite::{params, Connection, Result};
use std::path::Path;
use tracing::info;

use crate::models::{AlertData, AlertSummary, HistoryEntry};

/// Ensure the parent directory of the database file exists.
/// Creates it recursively if it doesn't.
pub fn ensure_db_dir(db_path: &str) {
    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(error = %e, path = %parent.display(), "Failed to create database directory");
            } else {
                info!(path = %parent.display(), "Created database directory");
            }
        }
    }
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans (
            scan_id      TEXT PRIMARY KEY,
            target_url   TEXT NOT NULL,
            scan_mode    TEXT NOT NULL,
            phase        TEXT NOT NULL,
            started_at   REAL NOT NULL,
            finished_at  REAL,
            high_count   INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count    INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        TEXT NOT NULL REFERENCES scans(scan_id),
            alert_key      TEXT NOT NULL,
            name           TEXT NOT NULL,
            risk           TEXT NOT NULL,
            confidence     TEXT NOT NULL,
            description    TEXT NOT NULL DEFAULT '',
            url            TEXT NOT NULL DEFAULT '',
            affected_urls  TEXT NOT NULL DEFAULT '',
            solution       TEXT NOT NULL DEFAULT '',
            reference      TEXT NOT NULL DEFAULT '',
            cweid          TEXT NOT NULL DEFAULT '',
            cwe_link       TEXT NOT NULL DEFAULT '',
            wascid         TEXT NOT NULL DEFAULT '',
            param          TEXT NOT NULL DEFAULT '',
            evidence       TEXT NOT NULL DEFAULT '',
            owasp_code     TEXT NOT NULL DEFAULT '',
            owasp_category TEXT NOT NULL DEFAULT ''
        );",
    )?;

    info!("Database initialized");
    Ok(())
}

pub fn save_scan(conn: &Connection, scan_id: &str, target_url: &str, scan_mode: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO scans (scan_id, target_url, scan_mode, phase, started_at)
         VALUES (?1, ?2, ?3, 'running', ?4)",
        params![scan_id, target_url, scan_mode, std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()],
    )?;
    Ok(())
}

pub fn update_scan_result(
    conn: &Connection,
    scan_id: &str,
    phase: &str,
    alerts: &[AlertData],
) -> Result<()> {
    let summary = AlertSummary::from_alerts(alerts);
    let finished_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let total = alerts.len() as u64;

    conn.execute(
        "UPDATE scans SET phase = ?1, finished_at = ?2, high_count = ?3, medium_count = ?4, low_count = ?5, total_alerts = ?6
         WHERE scan_id = ?7",
        params![phase, finished_at, summary.high as u64, summary.medium as u64, summary.low as u64, total, scan_id],
    )?;

    // Clear previous alerts for this scan, then insert fresh
    conn.execute("DELETE FROM alerts WHERE scan_id = ?1", params![scan_id])?;

    let mut stmt = conn.prepare(
        "INSERT INTO alerts (scan_id, alert_key, name, risk, confidence, description, url, affected_urls,
         solution, reference, cweid, cwe_link, wascid, param, evidence, owasp_code, owasp_category)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
    )?;

    for alert in alerts {
        stmt.execute(params![
            scan_id,
            alert.id,
            alert.name,
            alert.risk,
            alert.confidence,
            alert.description,
            alert.url,
            alert.affected_urls.join("; "),
            alert.solution,
            alert.reference,
            alert.cweid,
            alert.cwe_link,
            alert.wascid,
            alert.param,
            alert.evidence,
            alert.owasp_code,
            alert.owasp_category,
        ])?;
    }

    info!(scan_id = %scan_id, alerts = total, "Scan result saved to database");
    Ok(())
}

pub fn load_history(conn: &Connection) -> Vec<HistoryEntry> {
    let mut stmt = match conn.prepare(
        "SELECT scan_id, target_url, scan_mode, phase, started_at, finished_at,
                high_count, medium_count, low_count, total_alerts
         FROM scans ORDER BY started_at DESC",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let entries: Vec<HistoryEntry> = stmt
        .query_map([], |row| {
            let high: u64 = row.get(6)?;
            let medium: u64 = row.get(7)?;
            let low: u64 = row.get(8)?;
            let total: u64 = row.get(9)?;
            Ok(HistoryEntry {
                scan_id: row.get(0)?,
                target_url: row.get(1)?,
                scan_mode: row.get(2)?,
                phase: row.get(3)?,
                started_at: row.get(4)?,
                finished_at: row.get(5)?,
                alert_summary: AlertSummary {
                    high: high as usize,
                    medium: medium as usize,
                    low: low as usize,
                },
                total_alerts: total as usize,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();

    info!(count = entries.len(), "History loaded from database");
    entries
}

pub fn load_scan_results(conn: &Connection, scan_id: &str) -> Option<(HistoryEntry, Vec<AlertData>)> {
    let mut stmt = conn
        .prepare(
            "SELECT scan_id, target_url, scan_mode, phase, started_at, finished_at,
                    high_count, medium_count, low_count, total_alerts
             FROM scans WHERE scan_id = ?1",
        )
        .ok()?;
    let entry = stmt
        .query_row(params![scan_id], |row| {
            let high: u64 = row.get(6)?;
            let medium: u64 = row.get(7)?;
            let low: u64 = row.get(8)?;
            let total: u64 = row.get(9)?;
            Ok(HistoryEntry {
                scan_id: row.get(0)?,
                target_url: row.get(1)?,
                scan_mode: row.get(2)?,
                phase: row.get(3)?,
                started_at: row.get(4)?,
                finished_at: row.get(5)?,
                alert_summary: AlertSummary {
                    high: high as usize,
                    medium: medium as usize,
                    low: low as usize,
                },
                total_alerts: total as usize,
            })
        })
        .ok()?;

    let mut stmt = conn
        .prepare(
            "SELECT alert_key, name, risk, confidence, description, url, affected_urls,
                    solution, reference, cweid, cwe_link, wascid, param, evidence,
                    owasp_code, owasp_category
             FROM alerts WHERE scan_id = ?1",
        )
        .ok()?;
    let alerts: Vec<AlertData> = stmt
        .query_map(params![scan_id], |row| {
            Ok(AlertData {
                id: row.get(0)?,
                name: row.get(1)?,
                risk: row.get(2)?,
                confidence: row.get(3)?,
                description: row.get(4)?,
                url: row.get(5)?,
                affected_urls: row
                    .get::<_, String>(6)?
                    .split("; ")
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                solution: row.get(7)?,
                reference: row.get(8)?,
                cweid: row.get(9)?,
                cwe_link: row.get(10)?,
                wascid: row.get(11)?,
                param: row.get(12)?,
                evidence: row.get(13)?,
                owasp_code: row.get(14)?,
                owasp_category: row.get(15)?,
            })
        })
        .ok()?
        .filter_map(|r| r.ok())
        .collect();

    Some((entry, alerts))
}
