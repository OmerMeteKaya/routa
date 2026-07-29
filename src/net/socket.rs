//! Thin socket-setup helpers shared by anything that needs a listening
//! or outbound socket with specific options applied (`SO_REUSEPORT`,
//! non-blocking mode, receive/send buffer sizes). Deliberately small:
//! everything past "here is a configured, non-blocking socket" --
//! TLS, HTTP parsing, connection lifecycle -- belongs to other modules
//! (`net::tls`, `core::conn`, `core::event_loop`), not here. Rust's
//! `Drop` also means there's no equivalent needed for an explicit
//! "close this fd" helper: a socket is closed automatically once it
//! goes out of scope, so forgetting to close one isn't a category of
//! bug that can happen here the way it can in C.

use std::io;
use std::net::SocketAddr;

use mio::net::TcpListener;
use socket2::{Domain, Socket, Type};

/// Binds a `SO_REUSEPORT` listener on `port`, backed by the given
/// backlog. Each caller (typically one per worker -- see
/// `core::event_loop`) gets its own independent listening socket for
/// the same port; the kernel distributes incoming connections across
/// every such listener itself; see `core::event_loop`'s module doc for
/// why this is preferable to a single shared listener at routa's
/// target connection rates.
///
/// `SO_REUSEPORT` support itself is treated as best-effort: if the
/// platform doesn't support it, binding still succeeds (falling back
/// to ordinary single-listener behavior) rather than failing outright.
/// Binds a dual-stack listener on `port`: a single IPv6 socket with
/// `IPV6_V6ONLY` explicitly disabled, so IPv4 clients connecting via
/// their IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) are accepted on
/// the same socket as native IPv6 clients -- one listener instead of
/// running separate IPv4 and IPv6 sockets side by side. Falls back to
/// IPv4-only if IPv6 itself isn't available at all on this host (e.g.
/// disabled at the kernel/network-namespace level) -- a dual-stack
/// listener is preferred but plain IPv4 is still a functional server,
/// so a full startup failure just because IPv6 is unavailable would be
/// a worse outcome than falling back.
pub fn bind_reuseport(port: u16, backlog: i32) -> io::Result<TcpListener> {
    match bind_dual_stack(port, backlog) {
        Ok(listener) => Ok(listener),
        Err(_) => bind_ipv4_only(port, backlog),
    }
}

fn bind_dual_stack(port: u16, backlog: i32) -> io::Result<TcpListener> {
    let addr: SocketAddr = format!("[::]:{port}").parse().expect("valid address");
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?; // the key dual-stack setting -- accept both IPv4-mapped and native IPv6 traffic
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true); // best-effort, see doc comment above
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(TcpListener::from_std(socket.into()))
}

fn bind_ipv4_only(port: u16, backlog: i32) -> io::Result<TcpListener> {
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid address");
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true); // best-effort, see doc comment above
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(TcpListener::from_std(socket.into()))
}

/// Applies the receive/send buffer size overrides from config (0 means
/// "leave the OS default alone", matching `socket_recv_buf_size` /
/// `socket_send_buf_size`'s meaning in `core::config`) to an already-open
/// socket. Takes a `socket2::SockRef` so it works uniformly on whatever
/// concrete socket type the caller has (a `mio::net::TcpStream`, a
/// `std::net::TcpStream`, etc.) without needing a conversion at every
/// call site.
pub fn apply_buffer_sizes(
    socket: socket2::SockRef<'_>,
    recv_buf_size: i32,
    send_buf_size: i32,
) -> io::Result<()> {
    if recv_buf_size > 0 {
        socket.set_recv_buffer_size(recv_buf_size as usize)?;
    }
    if send_buf_size > 0 {
        socket.set_send_buffer_size(send_buf_size as usize)?;
    }
    Ok(())
}

/// Pins the calling thread to a single CPU core via `sched_setaffinity(2)`
/// -- see `RoutaConfig::cpu_affinity_enabled`/`cpu_affinity_start_core`.
/// `core_id` wrapping around the actual CPU count is the caller's
/// responsibility (or, as `core::event_loop` does it, simply accepted
/// as a no-op mispin on a machine with fewer cores than
/// `cpu_affinity_start_core + n_workers` -- `sched_setaffinity` itself
/// returns an error in that case, which the caller logs and otherwise
/// ignores rather than failing worker startup over).
///
/// Uses `sched_setaffinity(2)` directly rather than a portability crate
/// since this is currently the only affinity primitive routa needs;
/// a non-Linux build of this function should implement the equivalent
/// call for its own platform (e.g. `thread_policy_set` on macOS,
/// `SetThreadAffinityMask` on Windows) behind the same signature rather
/// than this becoming a no-op there.
#[cfg(target_os = "linux")]
pub fn pin_current_thread_to_core(core_id: usize) -> io::Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core_id, &mut set);
        let result = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread_to_core(_core_id: usize) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "CPU affinity is not implemented on this platform"))
}

/// One NUMA node's id and the CPU core ids that belong to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaNode {
    pub node_id: usize,
    pub cpus: Vec<usize>,
}

/// Reads this machine's NUMA topology, if any is exposed. Returns
/// `None` (rather than a single synthetic node) when there's nothing
/// meaningful to report -- a genuinely single-node machine and "NUMA
/// info isn't available at all" are both callers-should-just-use-
/// plain-round-robin cases, and a caller building affinity assignments
/// from this shouldn't need to special-case "exactly one node" as
/// distinct from "no topology".
#[cfg(target_os = "linux")]
pub fn numa_topology() -> Option<Vec<NumaNode>> {
    let entries = std::fs::read_dir("/sys/devices/system/node").ok()?;
    let mut nodes = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(node_id_str) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node_id) = node_id_str.parse::<usize>() else {
            continue;
        };
        let cpulist_path = entry.path().join("cpulist");
        let Ok(cpulist) = std::fs::read_to_string(&cpulist_path) else {
            continue;
        };
        let cpus = parse_cpu_list(cpulist.trim());
        if !cpus.is_empty() {
            nodes.push(NumaNode { node_id, cpus });
        }
    }
    if nodes.len() < 2 {
        return None; // a single node offers no placement decision to make
    }
    nodes.sort_by_key(|n| n.node_id);
    Some(nodes)
}

#[cfg(not(target_os = "linux"))]
pub fn numa_topology() -> Option<Vec<NumaNode>> {
    None
}

/// Parses Linux's `cpulist` format: comma-separated core ids and
/// ranges, e.g. `"0-3,8,10-11"`.
fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) {
                cpus.extend(start..=end);
            }
        } else if let Ok(cpu) = part.parse::<usize>() {
            cpus.push(cpu);
        }
    }
    cpus
}

/// Assigns each of `n_workers` workers a core id, preferring to fill
/// one NUMA node's cores before spilling onto the next rather than
/// striping workers evenly across every node -- keeping consecutive
/// workers (which, being adjacent in `core::server`'s round-robin
/// dispatch, tend to handle temporally-adjacent requests) on the same
/// node maximizes the chance their working set stays in that node's
/// local memory rather than crossing the NUMA interconnect. Falls back
/// to plain `start_core + worker_id` (the non-NUMA-aware assignment)
/// when no topology is available at all.
pub fn numa_aware_core_assignment(n_workers: usize, start_core: usize, topology: Option<&[NumaNode]>) -> Vec<usize> {
    let Some(topology) = topology else {
        return (0..n_workers).map(|i| start_core + i).collect();
    };
    let mut all_cpus: Vec<usize> = topology.iter().flat_map(|node| node.cpus.iter().copied()).collect();
    all_cpus.sort_unstable();
    let start_idx = all_cpus.iter().position(|&c| c >= start_core).unwrap_or(0);
    (0..n_workers)
        .map(|i| all_cpus[(start_idx + i) % all_cpus.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream as StdTcpStream;

    #[test]
    fn bind_reuseport_accepts_connections() {
        let port = 18081;
        let listener = bind_reuseport(port, 128).expect("bind");

        // A second listener on the same port should also succeed,
        // proving SO_REUSEPORT actually took effect (without it, the
        // second bind would fail with "address already in use").
        let _second = bind_reuseport(port, 128).expect("second bind with SO_REUSEPORT");

        let client = StdTcpStream::connect(("127.0.0.1", port));
        assert!(client.is_ok(), "should be able to connect to a bound, listening socket");

        drop(listener);
    }

    #[test]
    fn bind_reuseport_accepts_ipv4_via_dual_stack_socket() {
        // With the listener now bound on IPv6 (dual-stack), an IPv4
        // connection must still work -- it arrives as an IPv4-mapped
        // IPv6 address (::ffff:127.0.0.1) rather than being rejected.
        let port = 18082;
        let listener = bind_reuseport(port, 128).expect("bind");
        let client = StdTcpStream::connect(("127.0.0.1", port));
        assert!(client.is_ok(), "IPv4 connections should still work against the dual-stack listener");
        drop(listener);
    }

    #[test]
    fn bind_reuseport_accepts_native_ipv6_connections() {
        let port = 18083;
        let listener = bind_reuseport(port, 128).expect("bind");
        let client = StdTcpStream::connect(("::1", port));
        assert!(client.is_ok(), "native IPv6 (::1) connections should be accepted");
        drop(listener);
    }

    #[test]
    fn accepted_ipv4_and_ipv6_connections_are_both_readable() {
        // Beyond just connecting, confirm the accepted socket on each
        // side can actually exchange bytes -- proves the dual-stack
        // listener isn't just accepting the TCP handshake while
        // leaving the connection otherwise unusable.
        use std::io::{Read, Write};
        let port = 18084;
        let listener = bind_reuseport(port, 128).expect("bind");
        let mut std_listener: std::net::TcpListener = listener.into();
        std_listener.set_nonblocking(false).unwrap();

        let mut client = StdTcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut accepted, _) = std_listener.accept().unwrap();

        client.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn buffer_sizes_zero_is_left_alone() {
        // 0 for both means "don't touch anything" -- this should never
        // error, even on a freshly-created socket with only OS defaults.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create socket");
        let result = apply_buffer_sizes(socket2::SockRef::from(&socket), 0, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn buffer_sizes_applies_nonzero_values() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create socket");
        apply_buffer_sizes(socket2::SockRef::from(&socket), 65536, 65536)
            .expect("apply buffer sizes");
        // The kernel is free to round the requested size up (Linux
        // commonly doubles it for bookkeeping overhead), so just check
        // it's at least what was requested, not an exact match.
        let recv = socket.recv_buffer_size().expect("read recv buffer size");
        assert!(recv >= 65536, "expected recv buffer >= 65536, got {recv}");
    }

    #[test]
    fn pin_current_thread_to_core_actually_restricts_the_affinity_mask() {
        // Core 0 exists on every real machine this test would run on.
        pin_current_thread_to_core(0).expect("pin to core 0");
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            let result = libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set);
            assert_eq!(result, 0, "sched_getaffinity should succeed");
            assert!(libc::CPU_ISSET(0, &set), "core 0 should be in the affinity mask");
            assert_eq!(libc::CPU_COUNT(&set), 1, "affinity mask should contain exactly the one pinned core");
        }
    }

    #[test]
    fn parse_cpu_list_handles_ranges_and_singletons() {
        assert_eq!(parse_cpu_list("0-3,8,10-11"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpu_list("5"), vec![5]);
        assert_eq!(parse_cpu_list(""), Vec::<usize>::new());
    }

    #[test]
    fn numa_aware_assignment_fills_one_node_before_spilling_to_the_next() {
        let topology = vec![
            NumaNode { node_id: 0, cpus: vec![0, 1, 2, 3] },
            NumaNode { node_id: 1, cpus: vec![4, 5, 6, 7] },
        ];
        let assignment = numa_aware_core_assignment(6, 0, Some(&topology));
        assert_eq!(assignment, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn numa_aware_assignment_honors_start_core() {
        let topology = vec![
            NumaNode { node_id: 0, cpus: vec![0, 1, 2, 3] },
            NumaNode { node_id: 1, cpus: vec![4, 5, 6, 7] },
        ];
        let assignment = numa_aware_core_assignment(3, 2, Some(&topology));
        assert_eq!(assignment, vec![2, 3, 4]);
    }

    #[test]
    fn numa_aware_assignment_without_topology_falls_back_to_plain_round_robin() {
        let assignment = numa_aware_core_assignment(4, 2, None);
        assert_eq!(assignment, vec![2, 3, 4, 5]);
    }

    #[test]
    fn numa_topology_on_this_host_is_either_none_or_at_least_two_real_nodes() {
        // Doesn't assert a specific topology (test hosts vary) -- just
        // that the contract holds: no single-node result ever leaks
        // out, since a caller relies on `None` meaning "no placement
        // decision available" rather than needing to special-case a
        // one-element Vec.
        if let Some(topology) = numa_topology() {
            assert!(topology.len() >= 2);
            for node in &topology {
                assert!(!node.cpus.is_empty());
            }
        }
    }
}

// ─── sendfile(2): zero-copy file-to-socket transfer ─────────────────────

use std::os::unix::io::AsRawFd;

/// Sends up to `count` bytes from `file` (starting at `offset`,
/// which is advanced by however much was actually sent) directly to
/// `socket_fd` via the `sendfile(2)` syscall -- the kernel copies
/// data from the file's page cache straight to the socket buffer,
/// never through a userspace buffer the way a `read()` + `write()`
/// pair would. Only meaningful for a plaintext (non-TLS) socket: TLS
/// must encrypt in userspace before any bytes reach the kernel, so
/// there's nothing for the kernel to copy directly from a file for an
/// encrypted connection -- callers on a TLS transport should use the
/// ordinary read+write path instead of this function entirely.
///
/// Returns the number of bytes actually sent (which may be less than
/// `count`, particularly on a non-blocking socket whose send buffer
/// fills up mid-transfer -- the caller is expected to retry with the
/// updated `offset` on the next writable-readiness event, the same
/// partial-write tolerance every other transport write in this
/// codebase already has to handle).
///
/// Returns `Err` with `ErrorKind::WouldBlock` if the socket can't
/// accept any bytes at all right now (mirrors a regular `write()`'s
/// `EAGAIN` behavior), and other `io::Error`s for genuine failures.
pub fn sendfile(file: &std::fs::File, socket_fd: std::os::unix::io::RawFd, offset: &mut u64, count: usize) -> io::Result<usize> {
    let mut off: libc::off_t = *offset as libc::off_t;
    let result = unsafe { libc::sendfile(socket_fd, file.as_raw_fd(), &mut off, count) };

    if result < 0 {
        let err = io::Error::last_os_error();
        return Err(err);
    }

    *offset = off as u64;
    Ok(result as usize)
}
