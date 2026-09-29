//! Table definitions. Each lists its rows with sysinfo or netstat2, then getters pick
//! out the columns a query selects.

use crate::redact;
use duckdb_tables::{Bind, BoxError, Cell, ColType, Column, ListTable, Param};
use std::{path::Path, sync::LazyLock};
use sysinfo::{
    Disks, Networks, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, ThreadKind, UpdateKind, Users,
};

pub const REDACT_SETTING: &str = "os_redact";

/// Settings every table reads.
pub struct Opts {
    redact: bool,
}

fn opts(bind: &Bind) -> Opts {
    // Fail closed: if the setting can't be read, redact.
    Opts {
        redact: bind.setting(REDACT_SETTING).is_none_or(|v| v.to_bool()),
    }
}

fn micros(secs: u64) -> i64 {
    secs as i64 * 1_000_000
}

fn path_str(p: Option<&Path>) -> Option<String> {
    p.map(|p| p.to_string_lossy().into_owned())
}

fn user_names() -> std::collections::HashMap<u32, String> {
    Users::new_with_refreshed_list()
        .list()
        .iter()
        .map(|u| (**u.id(), u.name().to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// os_processes
// ---------------------------------------------------------------------------

pub struct Proc {
    pid: u32,
    ppid: Option<u32>,
    name: String,
    path: Option<String>,
    /// None when the command line can't be read (another user's process, without root).
    args: Option<Vec<String>>,
    uid: Option<u32>,
    user: Option<String>,
    state: String,
    start_time: u64,
    cpu_ms: u64,
    rss: u64,
    virtual_bytes: u64,
    cwd: Option<String>,
}

/// The process's cgroup path (Linux). cgroup v2's unified entry is preferred.
fn cgroup(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let entries: Vec<&str> = text.lines().filter_map(|l| l.splitn(3, ':').nth(2)).collect();
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .or(entries.first().copied())
        .map(String::from)
}

/// The container ID in a cgroup path: docker-<id>.scope, cri-containerd-<id>.scope, /docker/<id>, ...
fn container_id(cgroup: &str) -> Option<String> {
    static ID: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[0-9a-f]{64}").unwrap());
    ID.find_iter(cgroup).last().map(|m| m.as_str().to_string())
}

pub struct Processes;

impl ListTable for Processes {
    type Item = Proc;
    type Args = Opts;
    fn doc() -> &'static str {
        "Running processes, like ps. Command lines are redacted unless os_redact is false. \
            Other users' command lines, paths and working directories are NULL without root."
    }

    fn columns() -> &'static [Column<Proc>] {
        static COLUMNS: &[Column<Proc>] = &[
            Column { name: "pid", ty: ColType::Bigint, doc: "Process ID.", get: |p| Cell::Int(p.pid.into()) },
            Column { name: "ppid", ty: ColType::Bigint, doc: "Parent process ID.", get: |p| p.ppid.map(i64::from).into() },
            Column { name: "name", ty: ColType::Varchar, doc: "Process name.", get: |p| p.name.clone().into() },
            Column { name: "path", ty: ColType::Varchar, doc: "Executable path. Joins binary_info(path) from the binaries extension.", get: |p| p.path.clone().into() },
            Column { name: "cmdline", ty: ColType::Varchar, doc: "Arguments joined with spaces, secrets redacted.", get: |p| p.args.as_ref().map(|a| a.join(" ")).into() },
            Column { name: "args", ty: ColType::VarcharList, doc: "Arguments, secrets redacted.", get: |p| p.args.clone().into() },
            Column { name: "uid", ty: ColType::Bigint, doc: "Real user ID.", get: |p| p.uid.map(i64::from).into() },
            Column { name: "user", ty: ColType::Varchar, doc: "User name.", get: |p| p.user.clone().into() },
            Column { name: "state", ty: ColType::Varchar, doc: "run, sleep, idle, stop, zombie, ...", get: |p| p.state.clone().into() },
            Column { name: "start_time", ty: ColType::Timestamp, doc: "When the process started, UTC.", get: |p| Cell::Ts(micros(p.start_time)) },
            Column { name: "cpu_seconds", ty: ColType::Double, doc: "CPU time used since the process started.", get: |p| Cell::Float(p.cpu_ms as f64 / 1000.0) },
            Column { name: "rss_bytes", ty: ColType::Ubigint, doc: "Resident memory.", get: |p| Cell::UInt(p.rss) },
            Column { name: "virtual_bytes", ty: ColType::Ubigint, doc: "Virtual memory.", get: |p| Cell::UInt(p.virtual_bytes) },
            Column { name: "cwd", ty: ColType::Varchar, doc: "Working directory.", get: |p| p.cwd.clone().into() },
            Column { name: "cgroup", ty: ColType::Varchar, doc: "cgroup path (Linux; NULL elsewhere).", get: |p| cgroup(p.pid).into() },
            Column { name: "container_id", ty: ColType::Varchar, doc: "Container ID from the cgroup path (Linux; NULL if not in a container).", get: |p| cgroup(p.pid).and_then(|c| container_id(&c)).into() },
        ];
        COLUMNS
    }

    fn bind(bind: &Bind) -> Result<Opts, BoxError> {
        Ok(opts(bind))
    }

    fn list(opts: &Opts) -> Result<Vec<Proc>, BoxError> {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .with_cwd(UpdateKind::Always)
                .with_user(UpdateKind::Always)
                .with_memory()
                .with_cpu(),
        );
        let users = user_names();
        let mut out: Vec<Proc> = sys
            .processes()
            .values()
            // Linux lists threads as tasks; ps shows processes.
            .filter(|p| p.thread_kind() != Some(ThreadKind::Userland))
            .map(|p| {
                let args: Vec<String> = p.cmd().iter().map(|a| a.to_string_lossy().into_owned()).collect();
                let uid = p.user_id().map(|u| **u);
                Proc {
                    pid: p.pid().as_u32(),
                    ppid: p.parent().map(|p| p.as_u32()),
                    name: p.name().to_string_lossy().into_owned(),
                    path: path_str(p.exe()),
                    args: (!args.is_empty()).then(|| if opts.redact { redact::redact_args(&args) } else { args }),
                    uid,
                    user: uid.and_then(|u| users.get(&u).cloned()),
                    state: p.status().to_string().to_lowercase(),
                    start_time: p.start_time(),
                    cpu_ms: p.accumulated_cpu_time(),
                    rss: p.memory(),
                    virtual_bytes: p.virtual_memory(),
                    cwd: path_str(p.cwd()),
                }
            })
            .collect();
        out.sort_by_key(|p| p.pid);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// os_process_env
// ---------------------------------------------------------------------------

pub struct EnvVar {
    pid: u32,
    name: String,
    key: String,
    value: String,
}

pub struct EnvArgs {
    opts: Opts,
    pid: Option<u32>,
}

pub struct ProcessEnv;

impl ListTable for ProcessEnv {
    type Item = EnvVar;
    type Args = EnvArgs;
    fn doc() -> &'static str {
        "Environment variables of running processes, one row per variable. \
            Values are redacted unless os_redact is false. Only your own processes are visible without root."
    }

    fn columns() -> &'static [Column<EnvVar>] {
        static COLUMNS: &[Column<EnvVar>] = &[
            Column { name: "pid", ty: ColType::Bigint, doc: "Process ID.", get: |e| Cell::Int(e.pid.into()) },
            Column { name: "name", ty: ColType::Varchar, doc: "Process name.", get: |e| e.name.clone().into() },
            Column { name: "key", ty: ColType::Varchar, doc: "Variable name.", get: |e| e.key.clone().into() },
            Column { name: "value", ty: ColType::Varchar, doc: "Value, secrets redacted.", get: |e| e.value.clone().into() },
        ];
        COLUMNS
    }

    fn named() -> &'static [Param] {
        static NAMED: &[Param] = &[Param {
            name: "pid",
            ty: ColType::Bigint,
            doc: "Only read this process. Much faster than filtering with WHERE, which reads every process.",
        }];
        NAMED
    }

    fn bind(bind: &Bind) -> Result<EnvArgs, BoxError> {
        let pid = match bind.named("pid").map(|v| v.to_int64()) {
            Some(p) if !(0..=u32::MAX as i64).contains(&p) => return Err(format!("invalid pid {p}").into()),
            p => p.map(|p| p as u32),
        };
        Ok(EnvArgs { opts: opts(bind), pid })
    }

    fn list(args: &EnvArgs) -> Result<Vec<EnvVar>, BoxError> {
        let pids: Vec<sysinfo::Pid> = args.pid.map(sysinfo::Pid::from_u32).into_iter().collect();
        let which = if args.pid.is_some() { ProcessesToUpdate::Some(&pids) } else { ProcessesToUpdate::All };
        let mut sys = System::new();
        sys.refresh_processes_specifics(which, true, ProcessRefreshKind::nothing().with_environ(UpdateKind::Always));
        let mut out = Vec::new();
        for p in sys.processes().values().filter(|p| p.thread_kind() != Some(ThreadKind::Userland)) {
            let name = p.name().to_string_lossy();
            for entry in p.environ() {
                let entry = entry.to_string_lossy();
                let (key, value) = entry.split_once('=').unwrap_or((&entry, ""));
                out.push(EnvVar {
                    pid: p.pid().as_u32(),
                    name: name.to_string(),
                    key: key.to_string(),
                    value: if args.opts.redact { redact::redact_env(key, value) } else { value.to_string() },
                });
            }
        }
        out.sort_by(|a, b| (a.pid, &a.key).cmp(&(b.pid, &b.key)));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// os_sockets
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Sock {
    protocol: &'static str,
    family: &'static str,
    local_address: String,
    local_port: u16,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    state: Option<&'static str>,
    pid: Option<u32>,
}

fn tcp_state(s: &netstat2::TcpState) -> &'static str {
    use netstat2::TcpState as S;
    match s {
        S::Closed => "closed",
        S::Listen => "listen",
        S::SynSent => "syn_sent",
        S::SynReceived => "syn_received",
        S::Established => "established",
        S::FinWait1 => "fin_wait_1",
        S::FinWait2 => "fin_wait_2",
        S::CloseWait => "close_wait",
        S::Closing => "closing",
        S::LastAck => "last_ack",
        S::TimeWait => "time_wait",
        S::DeleteTcb => "delete_tcb",
        S::Unknown => "unknown",
    }
}

/// macOS embeds the interface index in link-local addresses (fe80:e::1); drop it so
/// addresses compare equal to os_interfaces.addresses.
fn clean_addr(addr: std::net::IpAddr) -> String {
    match addr {
        std::net::IpAddr::V6(v6) if v6.segments()[0] == 0xfe80 => {
            let mut seg = v6.segments();
            seg[1] = 0;
            std::net::Ipv6Addr::from(seg).to_string()
        }
        _ => addr.to_string(),
    }
}

pub struct Sockets;

impl ListTable for Sockets {
    type Item = Sock;
    type Args = ();
    fn doc() -> &'static str {
        "TCP and UDP sockets, like netstat or lsof -i: one row per owning process. \
            Join os_processes on pid. Without root, sockets of other users' processes may be missing."
    }

    fn columns() -> &'static [Column<Sock>] {
        static COLUMNS: &[Column<Sock>] = &[
            Column { name: "protocol", ty: ColType::Varchar, doc: "tcp or udp.", get: |s| s.protocol.into() },
            Column { name: "family", ty: ColType::Varchar, doc: "ipv4 or ipv6.", get: |s| s.family.into() },
            Column { name: "local_address", ty: ColType::Varchar, doc: "Local IP address.", get: |s| s.local_address.clone().into() },
            Column { name: "local_port", ty: ColType::Bigint, doc: "Local port.", get: |s| Cell::Int(s.local_port.into()) },
            Column { name: "remote_address", ty: ColType::Varchar, doc: "Remote IP address (TCP only).", get: |s| s.remote_address.clone().into() },
            Column { name: "remote_port", ty: ColType::Bigint, doc: "Remote port (TCP only).", get: |s| s.remote_port.map(i64::from).into() },
            Column { name: "state", ty: ColType::Varchar, doc: "TCP state: listen, established, time_wait, ... NULL for UDP.", get: |s| s.state.into() },
            Column { name: "pid", ty: ColType::Bigint, doc: "Owning process, or NULL if unknown.", get: |s| s.pid.map(i64::from).into() },
        ];
        COLUMNS
    }

    fn bind(_: &Bind) -> Result<(), BoxError> {
        Ok(())
    }

    fn list(_: &()) -> Result<Vec<Sock>, BoxError> {
        use netstat2::{AddressFamilyFlags as AF, ProtocolFlags as PF, ProtocolSocketInfo as P};
        let sockets = netstat2::get_sockets_info(AF::IPV4 | AF::IPV6, PF::TCP | PF::UDP)
            .map_err(|e| format!("listing sockets: {e}"))?;
        let mut out = Vec::new();
        for s in sockets {
            let base = match &s.protocol_socket_info {
                P::Tcp(t) => Sock {
                    protocol: "tcp",
                    family: if t.local_addr.is_ipv4() { "ipv4" } else { "ipv6" },
                    local_address: clean_addr(t.local_addr),
                    local_port: t.local_port,
                    remote_address: Some(clean_addr(t.remote_addr)),
                    remote_port: Some(t.remote_port),
                    state: Some(tcp_state(&t.state)),
                    pid: None,
                },
                P::Udp(u) => Sock {
                    protocol: "udp",
                    family: if u.local_addr.is_ipv4() { "ipv4" } else { "ipv6" },
                    local_address: clean_addr(u.local_addr),
                    local_port: u.local_port,
                    remote_address: None,
                    remote_port: None,
                    state: None,
                    pid: None,
                },
            };
            if s.associated_pids.is_empty() {
                out.push(base);
            } else {
                out.extend(s.associated_pids.iter().map(|&pid| Sock { pid: Some(pid), ..base.clone() }));
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// os_users
// ---------------------------------------------------------------------------

pub struct User {
    uid: u32,
    gid: u32,
    name: String,
    groups: Vec<String>,
}

pub struct UsersTable;

impl ListTable for UsersTable {
    type Item = User;
    type Args = ();
    fn doc() -> &'static str {
        "Local user accounts, including system accounts."
    }

    fn columns() -> &'static [Column<User>] {
        static COLUMNS: &[Column<User>] = &[
            Column { name: "uid", ty: ColType::Bigint, doc: "User ID.", get: |u| Cell::Int(u.uid.into()) },
            Column { name: "gid", ty: ColType::Bigint, doc: "Primary group ID.", get: |u| Cell::Int(u.gid.into()) },
            Column { name: "name", ty: ColType::Varchar, doc: "User name.", get: |u| u.name.clone().into() },
            Column { name: "groups", ty: ColType::VarcharList, doc: "Group names.", get: |u| u.groups.clone().into() },
        ];
        COLUMNS
    }

    fn bind(_: &Bind) -> Result<(), BoxError> {
        Ok(())
    }

    fn list(_: &()) -> Result<Vec<User>, BoxError> {
        let mut out: Vec<User> = Users::new_with_refreshed_list()
            .list()
            .iter()
            .map(|u| User {
                uid: **u.id(),
                gid: *u.group_id(),
                name: u.name().to_string(),
                groups: u.groups().iter().map(|g| g.name().to_string()).collect(),
            })
            .collect();
        out.sort_by_key(|u| u.uid);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// os_disks
// ---------------------------------------------------------------------------

pub struct DiskRow {
    name: String,
    mount_point: String,
    file_system: String,
    kind: String,
    total: u64,
    available: u64,
    removable: bool,
    read_only: bool,
}

pub struct DisksTable;

impl ListTable for DisksTable {
    type Item = DiskRow;
    type Args = ();
    fn doc() -> &'static str {
        "Mounted disks and their free space, like df."
    }

    fn columns() -> &'static [Column<DiskRow>] {
        static COLUMNS: &[Column<DiskRow>] = &[
            Column { name: "name", ty: ColType::Varchar, doc: "Device name.", get: |d| d.name.clone().into() },
            Column { name: "mount_point", ty: ColType::Varchar, doc: "Where it's mounted.", get: |d| d.mount_point.clone().into() },
            Column { name: "file_system", ty: ColType::Varchar, doc: "apfs, ext4, xfs, ...", get: |d| d.file_system.clone().into() },
            Column { name: "kind", ty: ColType::Varchar, doc: "ssd, hdd or unknown.", get: |d| d.kind.clone().into() },
            Column { name: "total_bytes", ty: ColType::Ubigint, doc: "Size.", get: |d| Cell::UInt(d.total) },
            Column { name: "available_bytes", ty: ColType::Ubigint, doc: "Free space available to unprivileged users.", get: |d| Cell::UInt(d.available) },
            Column { name: "removable", ty: ColType::Boolean, doc: "Removable media.", get: |d| Cell::Bool(d.removable) },
            Column { name: "read_only", ty: ColType::Boolean, doc: "Mounted read-only.", get: |d| Cell::Bool(d.read_only) },
        ];
        COLUMNS
    }

    fn bind(_: &Bind) -> Result<(), BoxError> {
        Ok(())
    }

    fn list(_: &()) -> Result<Vec<DiskRow>, BoxError> {
        Ok(Disks::new_with_refreshed_list()
            .list()
            .iter()
            .map(|d| DiskRow {
                name: d.name().to_string_lossy().into_owned(),
                mount_point: d.mount_point().to_string_lossy().into_owned(),
                file_system: d.file_system().to_string_lossy().into_owned(),
                kind: match d.kind() {
                    sysinfo::DiskKind::SSD => "ssd".into(),
                    sysinfo::DiskKind::HDD => "hdd".into(),
                    sysinfo::DiskKind::Unknown(_) => "unknown".into(),
                },
                total: d.total_space(),
                available: d.available_space(),
                removable: d.is_removable(),
                read_only: d.is_read_only(),
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// os_interfaces
// ---------------------------------------------------------------------------

pub struct Interface {
    name: String,
    mac: String,
    addresses: Vec<String>,
    mtu: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
}

pub struct Interfaces;

impl ListTable for Interfaces {
    type Item = Interface;
    type Args = ();
    fn doc() -> &'static str {
        "Network interfaces with their addresses and traffic counters since boot."
    }

    fn columns() -> &'static [Column<Interface>] {
        static COLUMNS: &[Column<Interface>] = &[
            Column { name: "name", ty: ColType::Varchar, doc: "Interface name.", get: |i| i.name.clone().into() },
            Column { name: "mac", ty: ColType::Varchar, doc: "MAC address.", get: |i| i.mac.clone().into() },
            Column { name: "addresses", ty: ColType::VarcharList, doc: "IP addresses with prefix length, e.g. 10.0.0.5/24.", get: |i| i.addresses.clone().into() },
            Column { name: "mtu", ty: ColType::Ubigint, doc: "MTU.", get: |i| Cell::UInt(i.mtu) },
            Column { name: "rx_bytes", ty: ColType::Ubigint, doc: "Bytes received.", get: |i| Cell::UInt(i.rx_bytes) },
            Column { name: "tx_bytes", ty: ColType::Ubigint, doc: "Bytes sent.", get: |i| Cell::UInt(i.tx_bytes) },
            Column { name: "rx_errors", ty: ColType::Ubigint, doc: "Receive errors.", get: |i| Cell::UInt(i.rx_errors) },
            Column { name: "tx_errors", ty: ColType::Ubigint, doc: "Send errors.", get: |i| Cell::UInt(i.tx_errors) },
        ];
        COLUMNS
    }

    fn bind(_: &Bind) -> Result<(), BoxError> {
        Ok(())
    }

    fn list(_: &()) -> Result<Vec<Interface>, BoxError> {
        let mut out: Vec<Interface> = Networks::new_with_refreshed_list()
            .list()
            .iter()
            .map(|(name, n)| Interface {
                name: name.clone(),
                mac: n.mac_address().to_string(),
                addresses: n.ip_networks().iter().map(|ip| format!("{}/{}", ip.addr, ip.prefix)).collect(),
                mtu: n.mtu(),
                rx_bytes: n.total_received(),
                tx_bytes: n.total_transmitted(),
                rx_errors: n.total_errors_on_received(),
                tx_errors: n.total_errors_on_transmitted(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// os_system
// ---------------------------------------------------------------------------

pub struct SystemRow {
    hostname: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    kernel_version: Option<String>,
    arch: String,
    cpus: u64,
    physical_cores: Option<u64>,
    memory_total: u64,
    memory_available: u64,
    swap_total: u64,
    swap_used: u64,
    boot_time: u64,
    uptime: u64,
    load: sysinfo::LoadAvg,
}

pub struct SystemTable;

impl ListTable for SystemTable {
    type Item = SystemRow;
    type Args = ();
    fn doc() -> &'static str {
        "One row describing this machine: OS, CPU, memory, uptime and load."
    }

    fn columns() -> &'static [Column<SystemRow>] {
        static COLUMNS: &[Column<SystemRow>] = &[
            Column { name: "hostname", ty: ColType::Varchar, doc: "Host name. Joins k8s_nodes(name) on Kubernetes nodes.", get: |s| s.hostname.clone().into() },
            Column { name: "os", ty: ColType::Varchar, doc: "OS or distribution name.", get: |s| s.os.clone().into() },
            Column { name: "os_version", ty: ColType::Varchar, doc: "OS version.", get: |s| s.os_version.clone().into() },
            Column { name: "kernel_version", ty: ColType::Varchar, doc: "Kernel version.", get: |s| s.kernel_version.clone().into() },
            Column { name: "arch", ty: ColType::Varchar, doc: "CPU architecture.", get: |s| s.arch.clone().into() },
            Column { name: "cpus", ty: ColType::Ubigint, doc: "Logical CPUs.", get: |s| Cell::UInt(s.cpus) },
            Column { name: "physical_cores", ty: ColType::Ubigint, doc: "Physical cores.", get: |s| s.physical_cores.into() },
            Column { name: "memory_total_bytes", ty: ColType::Ubigint, doc: "RAM.", get: |s| Cell::UInt(s.memory_total) },
            Column { name: "memory_available_bytes", ty: ColType::Ubigint, doc: "RAM available for new allocations.", get: |s| Cell::UInt(s.memory_available) },
            Column { name: "swap_total_bytes", ty: ColType::Ubigint, doc: "Swap size.", get: |s| Cell::UInt(s.swap_total) },
            Column { name: "swap_used_bytes", ty: ColType::Ubigint, doc: "Swap in use.", get: |s| Cell::UInt(s.swap_used) },
            Column { name: "boot_time", ty: ColType::Timestamp, doc: "When the machine booted, UTC.", get: |s| Cell::Ts(micros(s.boot_time)) },
            Column { name: "uptime_seconds", ty: ColType::Ubigint, doc: "Seconds since boot.", get: |s| Cell::UInt(s.uptime) },
            Column { name: "load_1", ty: ColType::Double, doc: "1-minute load average.", get: |s| Cell::Float(s.load.one) },
            Column { name: "load_5", ty: ColType::Double, doc: "5-minute load average.", get: |s| Cell::Float(s.load.five) },
            Column { name: "load_15", ty: ColType::Double, doc: "15-minute load average.", get: |s| Cell::Float(s.load.fifteen) },
        ];
        COLUMNS
    }

    fn bind(_: &Bind) -> Result<(), BoxError> {
        Ok(())
    }

    fn list(_: &()) -> Result<Vec<SystemRow>, BoxError> {
        let sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_memory(sysinfo::MemoryRefreshKind::everything())
                .with_cpu(sysinfo::CpuRefreshKind::nothing()),
        );
        Ok(vec![SystemRow {
            hostname: System::host_name(),
            os: System::name(),
            os_version: System::os_version(),
            kernel_version: System::kernel_version(),
            arch: System::cpu_arch(),
            cpus: sys.cpus().len() as u64,
            physical_cores: System::physical_core_count().map(|n| n as u64),
            memory_total: sys.total_memory(),
            memory_available: sys.available_memory(),
            swap_total: sys.total_swap(),
            swap_used: sys.used_swap(),
            boot_time: System::boot_time(),
            uptime: System::uptime(),
            load: System::load_average(),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_container_ids() {
        let id = "a".repeat(64);
        for path in [
            format!("/system.slice/docker-{id}.scope"),
            format!("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-{id}.scope"),
            format!("/docker/{id}"),
        ] {
            assert_eq!(container_id(&path).as_deref(), Some(id.as_str()), "{path}");
        }
        assert_eq!(container_id("/user.slice/user-1000.slice/session-2.scope"), None);
    }
}
