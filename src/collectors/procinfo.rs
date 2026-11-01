//! Resolves PIDs to executable details, verifies code signatures (Authenticode via PowerShell on
//! Windows, codesign on macOS, package ownership on Linux; see `crate::platform`), hashes
//! executables, and does reverse DNS for destinations that no captured DNS query explains.

use crate::model::{ExeMeta, SigStatus};
use crate::state::AppState;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub fn start_process_worker(state: Arc<AppState>, rx: mpsc::Receiver<u32>) {
    std::thread::Builder::new()
        .name("proc-info".into())
        .spawn(move || {
            let mut sys = System::new();
            let kind = ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::Always)
                .with_cmd(UpdateKind::Always)
                .with_user(UpdateKind::Always);
            let mut last_full = Instant::now() - Duration::from_secs(60);
            loop {
                let mut pids: Vec<u32> = vec![];
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(p) => pids.push(p),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(_) => {}
                }
                while let Ok(p) = rx.try_recv() {
                    pids.push(p);
                }
                // Retry any process whose info never loaded (e.g. raced with creation).
                let retry: Vec<u32> = state.procs.iter().filter(|p| !p.info_loaded && p.alive).map(|p| p.pid).collect();
                pids.extend(retry);
                pids.sort_unstable();
                pids.dedup();
                let full = last_full.elapsed() > Duration::from_secs(15);
                if full {
                    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
                    last_full = Instant::now();
                } else if !pids.is_empty() {
                    let sp: Vec<Pid> = pids.iter().map(|p| Pid::from_u32(*p)).collect();
                    sys.refresh_processes_specifics(ProcessesToUpdate::Some(&sp), true, kind);
                }
                for pid in pids {
                    // Kernel pseudo-processes the OS does not list (Windows pid 0 and 4).
                    if let Some((name, exe, user)) = crate::platform::pseudo_process(pid) {
                        state.apply_process_info(pid, name.into(), exe.into(), String::new(), 0, String::new(), 0, user.into());
                        continue;
                    }
                    let Some(p) = sys.process(Pid::from_u32(pid)) else {
                        state.mark_process_dead(pid);
                        continue;
                    };
                    let name = p.name().to_string_lossy().to_string();
                    let exe = p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
                    let cmd = p.cmd().iter().map(|c| c.to_string_lossy()).collect::<Vec<_>>().join(" ");
                    let ppid = p.parent().map(|x| x.as_u32()).unwrap_or(0);
                    let pname = p
                        .parent()
                        .and_then(|pp| sys.process(pp))
                        .map(|pp| pp.name().to_string_lossy().to_string())
                        .unwrap_or_default();
                    let user = p
                        .user_id()
                        .and_then(|u| sysinfo::Users::new_with_refreshed_list().get_user_by_id(u).map(|usr| usr.name().to_string()))
                        .unwrap_or_default();
                    state.apply_process_info(pid, name, exe, crate::util::truncate(&cmd, 500), ppid, pname, p.start_time() as i64 * 1000, user);
                }
                if full {
                    // Mark processes that vanished. Collect first: locking an entry while
                    // iterating the same map would deadlock.
                    let alive: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
                    let dead: Vec<u32> = state.procs.iter().filter(|p| p.alive && p.pid > 4 && !alive.contains(&p.pid)).map(|p| p.pid).collect();
                    for pid in dead {
                        state.mark_process_dead(pid);
                    }
                }
            }
        })
        .expect("spawn proc-info thread");
}

pub fn start_signature_worker(state: Arc<AppState>, rx: mpsc::Receiver<String>) {
    std::thread::Builder::new()
        .name("sig-worker".into())
        .spawn(move || loop {
            let mut batch: Vec<String> = vec![];
            match rx.recv() {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
            std::thread::sleep(Duration::from_millis(400));
            while let Ok(p) = rx.try_recv() {
                batch.push(p);
                if batch.len() >= 40 {
                    break;
                }
            }
            batch.sort();
            batch.dedup();
            let results = verify_signatures(&batch);
            for exe in batch {
                let (sig, signer) = results.get(&exe.to_ascii_lowercase()).cloned().unwrap_or((SigStatus::Unknown, None));
                let (sha, size) = hash_file(&exe);
                let meta = ExeMeta { sig, signer, sha256: sha.clone(), size, vt_positives: None, vt_total: None, vt_checked: false };
                state.apply_exe_meta(&exe, meta);
                if let (Some(sha), false) = (sha, state.cfg.read().virustotal.api_key.trim().is_empty()) {
                    if sig != SigStatus::Valid {
                        crate::collectors::vt::enqueue(exe.clone(), sha);
                    }
                }
            }
        })
        .expect("spawn sig-worker thread");
}

fn hash_file(path: &str) -> (Option<String>, u64) {
    let Ok(mut f) = std::fs::File::open(path) else { return (None, 0) };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        match std::io::Read::read(&mut f, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                hasher.update(&buf[..n]);
                if total > 512 * 1024 * 1024 {
                    return (None, total);
                }
            }
            Err(_) => return (None, total),
        }
    }
    (Some(hex::encode(hasher.finalize())), total)
}

/// Signature status per lower-cased path; the check itself is platform-specific.
fn verify_signatures(paths: &[String]) -> std::collections::HashMap<String, (SigStatus, Option<String>)> {
    crate::platform::verify_signatures(paths)
}

pub fn start_rdns_worker(state: Arc<AppState>, rx: mpsc::Receiver<IpAddr>) {
    std::thread::Builder::new()
        .name("rdns".into())
        .spawn(move || {
            for ip in rx {
                if state.ip_to_host.contains_key(&ip) {
                    continue;
                }
                if let Ok(name) = dns_lookup::lookup_addr(&ip) {
                    if name != ip.to_string() {
                        state.set_hostname(ip, name);
                    }
                }
            }
        })
        .expect("spawn rdns thread");
}
