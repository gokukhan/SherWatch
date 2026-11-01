//! Polls the OS TCP/UDP tables (GetExtendedTcpTable / GetExtendedUdpTable via netstat2)
//! once a second. Gives us connection state and listeners; ETW gives bytes.

use crate::model::Proto;
use crate::state::AppState;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub fn start(state: Arc<AppState>) {
    std::thread::Builder::new()
        .name("conn-table".into())
        .spawn(move || loop {
            poll(&state);
            std::thread::sleep(Duration::from_millis(1000));
        })
        .expect("spawn conn-table thread");
}

fn poll(state: &AppState) {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = match netstat2::get_sockets_info(af, proto) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("socket table error: {e}");
            return;
        }
    };
    let mut seen_listeners: HashSet<(Proto, u16, u32)> = HashSet::new();
    for s in sockets {
        let pid = s.associated_pids.first().copied().unwrap_or(0);
        match s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) => {
                if t.state == TcpState::Listen {
                    seen_listeners.insert((Proto::Tcp, t.local_port, pid));
                    state.upsert_listener(pid, Proto::Tcp, t.local_addr, t.local_port);
                    continue;
                }
                if t.remote_addr.is_unspecified() || t.remote_port == 0 {
                    continue;
                }
                if matches!(t.state, TcpState::TimeWait | TcpState::Closed) {
                    continue;
                }
                let st = tcp_state_str(&t.state);
                state.upsert_table_conn(
                    pid,
                    Proto::Tcp,
                    SocketAddr::new(t.local_addr, t.local_port),
                    SocketAddr::new(t.remote_addr, t.remote_port),
                    st,
                );
            }
            ProtocolSocketInfo::Udp(u) => {
                // A UDP socket bound to a port is a potential listener. Ephemeral ports are skipped.
                if u.local_port < 49152 && pid != 0 {
                    seen_listeners.insert((Proto::Udp, u.local_port, pid));
                    state.upsert_listener(pid, Proto::Udp, u.local_addr, u.local_port);
                }
                if !u.local_addr.is_unspecified() {
                    state.local_ips.insert(crate::util::normalize_ip(u.local_addr));
                }
            }
        }
    }
    // Loopback is always local.
    state.local_ips.insert(IpAddr::from([127, 0, 0, 1]));
    state.expire(&seen_listeners);
}

fn tcp_state_str(s: &TcpState) -> &'static str {
    match s {
        TcpState::Established => "established",
        TcpState::SynSent => "syn-sent",
        TcpState::SynReceived => "syn-recv",
        TcpState::FinWait1 => "fin-wait-1",
        TcpState::FinWait2 => "fin-wait-2",
        TcpState::CloseWait => "close-wait",
        TcpState::Closing => "closing",
        TcpState::LastAck => "last-ack",
        TcpState::TimeWait => "time-wait",
        TcpState::Closed => "closed",
        TcpState::Listen => "listen",
        TcpState::DeleteTcb => "delete-tcb",
        _ => "unknown",
    }
}
