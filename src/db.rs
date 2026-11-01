use crate::model::{Alert, Connection, DnsEvent};
use rusqlite::{params, Connection as Sql};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::mpsc;

pub enum DbMsg {
    Alert(Alert),
    Ack(i64),
    Traffic { ts: i64, pid: u32, name: String, exe: String, bytes_in: u64, bytes_out: u64 },
    ConnClosed { conn: Connection, name: String, exe: String },
    Dns(DnsEvent),
    KnownApp { exe: String, name: String, first_seen: i64 },
    Block { kind: String, target: String, rule: String, ts: i64 },
    Unblock { rule: String },
    Audit(AuditEntry),
    AuditReverted { id: i64, ts: i64 },
    Query(Box<dyn FnOnce(&Sql) + Send>),
}

/// One response action taken through the app (terminate, block, unblock, trust, untrust) and whether
/// it was later reverted. `detail` carries what a revert needs (rule name, path, hash) as JSON.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: i64,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub ok: bool,
    pub result: String,
    pub reverted_ts: Option<i64>,
    pub revert_of: Option<i64>,
}

#[derive(Clone)]
pub struct Db {
    tx: mpsc::Sender<DbMsg>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficBucket {
    pub ts: i64,
    pub name: String,
    pub exe: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockRule {
    pub id: i64,
    pub kind: String,
    pub target: String,
    pub rule: String,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnownApp {
    pub exe: String,
    pub name: String,
    pub first_seen: i64,
}

impl Db {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let sql = Sql::open(&path)?;
        sql.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY, ts INTEGER, severity TEXT, rule TEXT, title TEXT, detail TEXT,
                pid INTEGER, process TEXT, exe TEXT, remote TEXT, count INTEGER DEFAULT 1, acked INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
            CREATE TABLE IF NOT EXISTS traffic(
                ts INTEGER, pid INTEGER, name TEXT, exe TEXT, bytes_in INTEGER, bytes_out INTEGER);
            CREATE INDEX IF NOT EXISTS traffic_ts ON traffic(ts);
            CREATE TABLE IF NOT EXISTS conn_log(
                id INTEGER PRIMARY KEY, ts_start INTEGER, ts_end INTEGER, proto TEXT, pid INTEGER, name TEXT, exe TEXT,
                laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER, country TEXT, city TEXT, hostname TEXT,
                bytes_in INTEGER, bytes_out INTEGER, intel TEXT, flags TEXT);
            CREATE INDEX IF NOT EXISTS conn_log_ts ON conn_log(ts_start);
            CREATE TABLE IF NOT EXISTS dns_log(
                id INTEGER PRIMARY KEY, ts INTEGER, pid INTEGER, process TEXT, query TEXT, qtype INTEGER, status INTEGER, results TEXT, flags TEXT);
            CREATE INDEX IF NOT EXISTS dns_log_ts ON dns_log(ts);
            CREATE TABLE IF NOT EXISTS known_apps(exe TEXT PRIMARY KEY, name TEXT, first_seen INTEGER);
            CREATE TABLE IF NOT EXISTS blocks(id INTEGER PRIMARY KEY, kind TEXT, target TEXT, rule TEXT UNIQUE, ts INTEGER);
            CREATE TABLE IF NOT EXISTS cve_cache(id TEXT PRIMARY KEY, cpe TEXT, ts INTEGER);
            CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY, ts INTEGER, action TEXT, target TEXT, detail TEXT, ok INTEGER, result TEXT,
                reverted_ts INTEGER, revert_of INTEGER);
            "#,
        )?;
        let (tx, rx) = mpsc::channel::<DbMsg>();
        std::thread::Builder::new().name("db-writer".into()).spawn(move || writer_loop(sql, rx))?;
        Ok(Self { tx })
    }

    pub fn send(&self, msg: DbMsg) {
        let _ = self.tx.send(msg);
    }

    /// Run a read query on the writer thread and await the result.
    pub async fn query<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Sql) -> rusqlite::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.send(DbMsg::Query(Box::new(move |sql| {
            let _ = rtx.send(f(sql).map_err(|e| e.to_string()));
        })));
        match rrx.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => anyhow::bail!(e),
            Err(_) => anyhow::bail!("db thread gone"),
        }
    }

    fn query_blocking<T: Send + 'static>(&self, f: impl FnOnce(&Sql) -> T + Send + 'static) -> Option<T> {
        let (rtx, rrx) = mpsc::channel();
        self.send(DbMsg::Query(Box::new(move |sql| {
            let _ = rtx.send(f(sql));
        })));
        rrx.recv().ok()
    }

    pub fn load_known_apps(&self) -> Vec<KnownApp> {
        self.query_blocking(|sql| {
            let mut out = vec![];
            if let Ok(mut st) = sql.prepare("SELECT exe, name, first_seen FROM known_apps") {
                if let Ok(rows) = st.query_map([], |r| Ok(KnownApp { exe: r.get(0)?, name: r.get(1)?, first_seen: r.get(2)? })) {
                    out = rows.flatten().collect();
                }
            }
            out
        })
        .unwrap_or_default()
    }

    pub fn load_recent_alerts(&self, limit: usize) -> Vec<Alert> {
        self.query_blocking(move |sql| recent_alerts(sql, limit).unwrap_or_default()).unwrap_or_default()
    }

    pub fn next_alert_id(&self) -> i64 {
        self.query_blocking(|sql| sql.query_row("SELECT COALESCE(MAX(id),0) FROM alerts", [], |r| r.get::<_, i64>(0)).unwrap_or(0))
            .unwrap_or(0)
    }
}

pub fn audit_list(sql: &Sql, limit: usize) -> rusqlite::Result<Vec<AuditEntry>> {
    let mut st = sql.prepare("SELECT id, ts, action, target, detail, ok, result, reverted_ts, revert_of FROM audit ORDER BY ts DESC LIMIT ?1")?;
    let rows = st.query_map(params![limit as i64], |r| {
        Ok(AuditEntry {
            id: r.get(0)?,
            ts: r.get(1)?,
            action: r.get(2)?,
            target: r.get(3)?,
            detail: r.get(4)?,
            ok: r.get::<_, i64>(5)? != 0,
            result: r.get(6)?,
            reverted_ts: r.get(7)?,
            revert_of: r.get(8)?,
        })
    })?;
    Ok(rows.flatten().collect())
}

pub fn audit_get(sql: &Sql, id: i64) -> rusqlite::Result<Option<AuditEntry>> {
    Ok(audit_list(sql, 100_000)?.into_iter().find(|e| e.id == id))
}

pub fn blocks(sql: &Sql) -> rusqlite::Result<Vec<BlockRule>> {
    let mut st = sql.prepare("SELECT id, kind, target, rule, ts FROM blocks ORDER BY ts DESC")?;
    let rows = st.query_map([], |r| {
        Ok(BlockRule { id: r.get(0)?, kind: r.get(1)?, target: r.get(2)?, rule: r.get(3)?, ts: r.get(4)? })
    })?;
    Ok(rows.flatten().collect())
}

pub fn recent_alerts(sql: &Sql, limit: usize) -> rusqlite::Result<Vec<Alert>> {
    let mut st = sql.prepare(
        "SELECT id, ts, severity, rule, title, detail, pid, process, exe, remote, count, acked FROM alerts ORDER BY ts DESC LIMIT ?1",
    )?;
    let rows = st.query_map(params![limit as i64], |r| {
        Ok(Alert {
            id: r.get(0)?,
            ts: r.get(1)?,
            severity: crate::model::Severity::parse(&r.get::<_, String>(2)?),
            rule: r.get(3)?,
            title: r.get(4)?,
            detail: r.get(5)?,
            pid: r.get::<_, i64>(6)? as u32,
            process: r.get(7)?,
            exe: r.get(8)?,
            remote: r.get(9)?,
            count: r.get::<_, i64>(10)? as u32,
            acked: r.get::<_, i64>(11)? != 0,
        })
    })?;
    Ok(rows.flatten().collect())
}

pub fn alerts_since(sql: &Sql, since: i64) -> rusqlite::Result<Vec<Alert>> {
    let mut st = sql.prepare(
        "SELECT id, ts, severity, rule, title, detail, pid, process, exe, remote, count, acked FROM alerts WHERE ts >= ?1 ORDER BY ts DESC LIMIT 5000",
    )?;
    let rows = st.query_map(params![since], |r| {
        Ok(Alert {
            id: r.get(0)?,
            ts: r.get(1)?,
            severity: crate::model::Severity::parse(&r.get::<_, String>(2)?),
            rule: r.get(3)?,
            title: r.get(4)?,
            detail: r.get(5)?,
            pid: r.get::<_, i64>(6)? as u32,
            process: r.get(7)?,
            exe: r.get(8)?,
            remote: r.get(9)?,
            count: r.get::<_, i64>(10)? as u32,
            acked: r.get::<_, i64>(11)? != 0,
        })
    })?;
    Ok(rows.flatten().collect())
}

pub fn traffic_history(sql: &Sql, since: i64, bucket_ms: i64) -> rusqlite::Result<Vec<TrafficBucket>> {
    let mut st = sql.prepare(
        "SELECT (ts / ?2) * ?2 AS b, name, exe, SUM(bytes_in), SUM(bytes_out) FROM traffic WHERE ts >= ?1 GROUP BY b, exe ORDER BY b",
    )?;
    let rows = st.query_map(params![since, bucket_ms], |r| {
        Ok(TrafficBucket {
            ts: r.get(0)?,
            name: r.get(1)?,
            exe: r.get(2)?,
            bytes_in: r.get::<_, i64>(3)? as u64,
            bytes_out: r.get::<_, i64>(4)? as u64,
        })
    })?;
    Ok(rows.flatten().collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnLogRow {
    pub ts_start: i64,
    pub ts_end: i64,
    pub proto: String,
    pub pid: i64,
    pub name: String,
    pub exe: String,
    pub raddr: String,
    pub rport: i64,
    pub country: Option<String>,
    pub hostname: Option<String>,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub intel: Option<String>,
    pub flags: String,
}

pub fn conn_history(sql: &Sql, since: i64, limit: usize) -> rusqlite::Result<Vec<ConnLogRow>> {
    let mut st = sql.prepare(
        "SELECT ts_start, ts_end, proto, pid, name, exe, raddr, rport, country, hostname, bytes_in, bytes_out, intel, flags FROM conn_log WHERE ts_start >= ?1 ORDER BY ts_start DESC LIMIT ?2",
    )?;
    let rows = st.query_map(params![since, limit as i64], |r| {
        Ok(ConnLogRow {
            ts_start: r.get(0)?,
            ts_end: r.get(1)?,
            proto: r.get(2)?,
            pid: r.get(3)?,
            name: r.get(4)?,
            exe: r.get(5)?,
            raddr: r.get(6)?,
            rport: r.get(7)?,
            country: r.get(8)?,
            hostname: r.get(9)?,
            bytes_in: r.get(10)?,
            bytes_out: r.get(11)?,
            intel: r.get(12)?,
            flags: r.get(13)?,
        })
    })?;
    Ok(rows.flatten().collect())
}

fn writer_loop(mut sql: Sql, rx: mpsc::Receiver<DbMsg>) {
    let mut pending_traffic: Vec<(i64, u32, String, String, u64, u64)> = vec![];
    let mut last_flush = std::time::Instant::now();
    let mut last_prune = std::time::Instant::now();
    loop {
        let msg = match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(m) => Some(m),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if let Some(msg) = msg {
            match msg {
                DbMsg::Alert(a) => {
                    let _ = sql.execute(
                        "INSERT OR REPLACE INTO alerts(id, ts, severity, rule, title, detail, pid, process, exe, remote, count, acked) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                        params![a.id, a.ts, a.severity.as_str(), a.rule, a.title, a.detail, a.pid as i64, a.process, a.exe, a.remote, a.count as i64, a.acked as i64],
                    );
                }
                DbMsg::Ack(id) => {
                    let _ = sql.execute("UPDATE alerts SET acked=1 WHERE id=?1", params![id]);
                }
                DbMsg::Traffic { ts, pid, name, exe, bytes_in, bytes_out } => {
                    pending_traffic.push((ts, pid, name, exe, bytes_in, bytes_out));
                }
                DbMsg::ConnClosed { conn, name, exe } => {
                    let _ = sql.execute(
                        "INSERT INTO conn_log(ts_start, ts_end, proto, pid, name, exe, laddr, lport, raddr, rport, country, city, hostname, bytes_in, bytes_out, intel, flags) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                        params![
                            conn.first_seen, conn.last_seen, conn.proto.as_str(), conn.pid as i64, name, exe,
                            conn.local_addr.to_string(), conn.local_port as i64, conn.remote_addr.to_string(), conn.remote_port as i64,
                            conn.country, conn.city, conn.hostname, conn.bytes_in as i64, conn.bytes_out as i64, conn.intel, conn.flags.join(",")
                        ],
                    );
                }
                DbMsg::Dns(d) => {
                    let _ = sql.execute(
                        "INSERT INTO dns_log(ts, pid, process, query, qtype, status, results, flags) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                        params![
                            d.ts, d.pid as i64, d.process, d.query, d.qtype as i64, d.status as i64,
                            d.results.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(";"), d.flags.join(",")
                        ],
                    );
                }
                DbMsg::KnownApp { exe, name, first_seen } => {
                    let _ = sql.execute(
                        "INSERT OR IGNORE INTO known_apps(exe, name, first_seen) VALUES(?1,?2,?3)",
                        params![exe, name, first_seen],
                    );
                }
                DbMsg::Block { kind, target, rule, ts } => {
                    let _ = sql.execute(
                        "INSERT OR REPLACE INTO blocks(kind, target, rule, ts) VALUES(?1,?2,?3,?4)",
                        params![kind, target, rule, ts],
                    );
                }
                DbMsg::Unblock { rule } => {
                    let _ = sql.execute("DELETE FROM blocks WHERE rule=?1", params![rule]);
                }
                DbMsg::Audit(a) => {
                    let _ = sql.execute(
                        "INSERT INTO audit(ts, action, target, detail, ok, result, reverted_ts, revert_of) VALUES(?1,?2,?3,?4,?5,?6,NULL,?7)",
                        params![a.ts, a.action, a.target, a.detail, a.ok as i64, a.result, a.revert_of],
                    );
                }
                DbMsg::AuditReverted { id, ts } => {
                    let _ = sql.execute("UPDATE audit SET reverted_ts=?1 WHERE id=?2", params![ts, id]);
                }
                DbMsg::Query(f) => f(&sql),
            }
        }
        if !pending_traffic.is_empty() && (pending_traffic.len() >= 500 || last_flush.elapsed().as_secs() >= 10) {
            if let Ok(tx) = sql.transaction() {
                {
                    if let Ok(mut st) = tx.prepare_cached(
                        "INSERT INTO traffic(ts, pid, name, exe, bytes_in, bytes_out) VALUES(?1,?2,?3,?4,?5,?6)",
                    ) {
                        for (ts, pid, name, exe, bi, bo) in pending_traffic.drain(..) {
                            let _ = st.execute(params![ts, pid as i64, name, exe, bi as i64, bo as i64]);
                        }
                    }
                }
                let _ = tx.commit();
            }
            last_flush = std::time::Instant::now();
        }
        // Keep the database bounded: 30 days of detail.
        if last_prune.elapsed().as_secs() > 3600 {
            let cutoff = crate::util::now_ms() - 30 * 24 * 3600 * 1000;
            let _ = sql.execute("DELETE FROM traffic WHERE ts < ?1", params![cutoff]);
            let _ = sql.execute("DELETE FROM conn_log WHERE ts_start < ?1", params![cutoff]);
            let _ = sql.execute("DELETE FROM dns_log WHERE ts < ?1", params![cutoff]);
            last_prune = std::time::Instant::now();
        }
    }
}
