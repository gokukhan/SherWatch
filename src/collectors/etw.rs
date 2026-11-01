//! Event Tracing for Windows consumers.
//!  - Microsoft-Windows-Kernel-Network: per-process TCP/UDP send and receive sizes (no driver needed).
//!  - Microsoft-Windows-DNS-Client: every DNS query a process makes and what it resolved to.
//! Both need administrator rights.

use crate::model::{DnsEvent, Proto};
use crate::state::{AppState, Dir};
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, TraceFlags};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

static STATE: OnceLock<Arc<AppState>> = OnceLock::new();
/// Port byte order in the kernel-network payload: 0 undecided, 1 network order (swap), 2 host order.
/// Decided at runtime by matching the first TCP events against the OS connection table.
static PORT_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static PORT_VOTES: [std::sync::atomic::AtomicU32; 2] = [std::sync::atomic::AtomicU32::new(0), std::sync::atomic::AtomicU32::new(0)];

fn decide_ports(state: &AppState, pid: u32, raw_sport: u16, raw_dport: u16, daddr: IpAddr) -> (u16, u16) {
    match PORT_MODE.load(Ordering::Relaxed) {
        1 => return (u16::from_be(raw_sport), u16::from_be(raw_dport)),
        2 => return (raw_sport, raw_dport),
        _ => {}
    }
    let remote_ip = crate::util::normalize_ip(daddr);
    let swapped = (u16::from_be(raw_sport), u16::from_be(raw_dport));
    let hit = |lp: u16, rp: u16| state.conns.iter().any(|c| c.pid == pid && c.local_port == lp && c.remote_port == rp && c.remote_addr == remote_ip);
    if hit(swapped.0, swapped.1) {
        PORT_VOTES[0].fetch_add(1, Ordering::Relaxed);
    } else if hit(raw_sport, raw_dport) {
        PORT_VOTES[1].fetch_add(1, Ordering::Relaxed);
    }
    let (a, b) = (PORT_VOTES[0].load(Ordering::Relaxed), PORT_VOTES[1].load(Ordering::Relaxed));
    if a + b >= 12 {
        let mode = if a >= b { 1 } else { 2 };
        PORT_MODE.store(mode, Ordering::Relaxed);
        tracing::info!("ETW port byte order decided: {} ({a} vs {b} votes)", if mode == 1 { "network order" } else { "host order" });
    }
    swapped
}
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const TRACE_NAME: &str = "SherWatch";
/// Session name used before the rename; stopped at start in case a crashed old build left it running.
const LEGACY_TRACE_NAME: &str = "NetMonitorCommandCenter";

fn net_callback(record: &EventRecord, locator: &SchemaLocator) {
    let Some(state) = STATE.get() else { return };
    let id = record.event_id();
    // 10/26 TCP send v4/v6, 11/27 TCP recv, 42/58 UDP send, 43/59 UDP recv,
    // 12/28 TCP connect, 15/31 TCP accept.
    let (proto, dir) = match id {
        10 | 26 => (Proto::Tcp, Some(Dir::Out)),
        11 | 27 => (Proto::Tcp, Some(Dir::In)),
        42 | 58 => (Proto::Udp, Some(Dir::Out)),
        43 | 59 => (Proto::Udp, Some(Dir::In)),
        12 | 28 | 15 | 31 => (Proto::Tcp, None),
        _ => return,
    };
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let pid: u32 = parser.try_parse("PID").unwrap_or_else(|_| record.process_id());
    let daddr: IpAddr = match parser.try_parse("daddr") {
        Ok(a) => a,
        Err(_) => return,
    };
    let saddr: IpAddr = match parser.try_parse("saddr") {
        Ok(a) => a,
        Err(_) => return,
    };
    let raw_dport: u16 = parser.try_parse::<u16>("dport").unwrap_or(0);
    let raw_sport: u16 = parser.try_parse::<u16>("sport").unwrap_or(0);
    let (sport, dport) = if proto == Proto::Tcp {
        decide_ports(state, pid, raw_sport, raw_dport, daddr)
    } else {
        match PORT_MODE.load(Ordering::Relaxed) {
            2 => (raw_sport, raw_dport),
            _ => (u16::from_be(raw_sport), u16::from_be(raw_dport)),
        }
    };
    state.etw_events.fetch_add(1, Ordering::Relaxed);
    match dir {
        Some(d) => {
            let size: u32 = parser.try_parse("size").unwrap_or(0);
            // For these events saddr is the local end and daddr the remote end.
            state.record_flow(pid, proto, SocketAddr::new(saddr, sport), SocketAddr::new(daddr, dport), d, size);
        }
        None => {
            if id == 12 || id == 28 {
                state.note_connect(pid, daddr);
            } else {
                state.note_accept(pid, daddr);
            }
        }
    }
}

fn dns_callback(record: &EventRecord, locator: &SchemaLocator) {
    let Some(state) = STATE.get() else { return };
    if record.event_id() != 3008 {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let query: String = parser.try_parse("QueryName").unwrap_or_default();
    if query.is_empty() {
        return;
    }
    let qtype: u32 = parser.try_parse("QueryType").unwrap_or(0);
    let status: u32 = parser.try_parse("QueryStatus").or_else(|_| parser.try_parse("Status")).unwrap_or(0);
    let results: String = parser.try_parse("QueryResults").unwrap_or_default();
    let mut ips = vec![];
    for tok in results.split(';') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        // Entries look like "type: 5 cname.example;1.2.3.4;" - keep the plain IPs.
        let cand = t.rsplit(' ').next().unwrap_or(t);
        if let Ok(ip) = cand.parse::<IpAddr>() {
            ips.push(ip);
        }
    }
    state.etw_events.fetch_add(1, Ordering::Relaxed);
    state.record_dns(DnsEvent {
        ts: crate::util::now_ms(),
        pid: record.process_id(),
        process: String::new(),
        query,
        qtype,
        status,
        results: ips,
        flags: vec![],
    });
}

pub fn start(state: Arc<AppState>) {
    let _ = STATE.set(state.clone());
    // A trace with our name may linger from a crashed run; stop it first (old name too).
    for name in [TRACE_NAME, LEGACY_TRACE_NAME] {
        let _ = crate::util::quiet(
            std::process::Command::new("logman")
                .args(["stop", name, "-ets"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()),
        )
        .status();
    }

    let net = Provider::by_guid(KERNEL_NETWORK).add_callback(net_callback).build();
    let dns = Provider::by_guid(DNS_CLIENT)
        .add_callback(dns_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    match UserTrace::new().named(TRACE_NAME.to_string()).enable(net).enable(dns).start_and_process() {
        Ok(trace) => {
            state.etw_active.store(true, Ordering::Relaxed);
            tracing::info!("ETW trace started (kernel network + DNS client)");
            // Keep the trace alive for the life of the process.
            std::mem::forget(trace);
        }
        Err(e) => {
            let msg = format!("ETW trace could not start: {e:?}. Per-process byte counts and DNS capture need administrator rights.");
            tracing::error!("{msg}");
            *state.etw_error.write() = Some(msg);
        }
    }
}

#[allow(dead_code)]
pub fn stop() {
    let _ = crate::util::quiet(std::process::Command::new("logman").args(["stop", TRACE_NAME, "-ets"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())).status();
}

#[allow(dead_code)]
fn _assert_trait<T: TraceTrait>() {}
