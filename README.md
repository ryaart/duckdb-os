# os: the operating system as tables

A read-only DuckDB extension for investigating a machine: processes, sockets, users, disks, interfaces and system info.
It covers the part of [osquery](https://osquery.io) that investigations use most, on macOS and Linux, as plain table functions that join with each other and with anything else DuckDB can read.

```sql
LOAD os;

-- what's listening, and what is it?
SELECT s.protocol, s.local_address, s.local_port, p.pid, p.name, p.cmdline
FROM os_sockets() s JOIN os_processes() p USING (pid)
WHERE s.state = 'listen' ORDER BY s.local_port;

-- biggest memory users
SELECT pid, name, user, rss_bytes // 1048576 AS rss_mb FROM os_processes() ORDER BY rss_bytes DESC LIMIT 10;

-- which running processes link against OpenSSL? (with the binaries extension; table
-- functions only take literal arguments, so scan a glob and join on path)
SELECT DISTINCT p.pid, p.path, l.library
FROM binary_libraries('/usr/bin/*') l JOIN os_processes() p ON p.path = l.path
WHERE l.library LIKE '%ssl%' OR l.library LIKE '%crypto%';

-- what's in this process's environment?
SELECT key, value FROM os_process_env(pid := 4242);

-- what can I query?
SELECT * FROM os_describe();
```

## Functions

Call `os_describe()` for every function, column, parameter and setting, with descriptions.

| function | one row per | columns |
|---|---|---|
| `os_processes()` | process | `pid, ppid, name, path, cmdline, args[], uid, user, state, start_time, cpu_seconds, rss_bytes, virtual_bytes, cwd, cgroup, container_id` |
| `os_process_env(pid :=)` | environment variable | `pid, name, key, value` |
| `os_sockets()` | TCP/UDP socket and owning process | `protocol, family, local_address, local_port, remote_address, remote_port, state, pid` |
| `os_users()` | user account | `uid, gid, name, groups[]` |
| `os_disks()` | mounted disk | `name, mount_point, file_system, kind, total_bytes, available_bytes, removable, read_only` |
| `os_interfaces()` | network interface | `name, mac, addresses[], mtu, rx_bytes, tx_bytes, rx_errors, tx_errors` |
| `os_system()` | (one row) | `hostname, os, os_version, kernel_version, arch, cpus, physical_cores, memory_*_bytes, swap_*_bytes, boot_time, uptime_seconds, load_1, load_5, load_15` |

Timestamps are UTC.
- `cgroup` and `container_id` are Linux-only and read only when selected. `container_id` is the 64-hex ID in the cgroup path (Docker, containerd, CRI-O).
- `os_sockets.local_address` matches the addresses in `os_interfaces.addresses` (without the prefix), including IPv6 link-local addresses.

**Filter with arguments, not WHERE.** DuckDB's C API doesn't pass WHERE clauses to table functions, so `os_process_env() WHERE pid = 42` reads every process's environment before filtering. `os_process_env(pid := 42)` reads only that one.

**Permissions.** Without root, other users' processes still appear, but their `cmdline`, `args` and `cwd` are NULL. `os_process_env` only sees processes the current user can inspect. On macOS, `os_sockets` may miss sockets owned by other users' processes.

## Secrets

Command lines and environment variables often contain secrets. By default they're redacted:

```
--password=<redacted:d16342c6>   --token <redacted:fa3d9187>   postgres://app:<redacted:23527290>@db/x
```

- **What's redacted.**
  - Values of flags and variables with secret-sounding names: `--password=x`, `--token x`, `API_KEY=x`, `DB_PASSWORD`, `*_SECRET`, ...
  - Names that point at a secret rather than holding one (`--password-file`, `TOKEN_PATH`) are left alone.
  - Anywhere in a value: URL passwords, `Authorization:` headers and bearer tokens, GitHub/GitLab/Slack/OpenAI/Anthropic/AWS/Google keys, JWTs and PEM private keys.
- **Fingerprints.** The 8 hex digits are a keyed hash, so the same secret gets the same fingerprint everywhere in a session. That lets you tell whether two processes use the same password, or whether a token changed, without seeing it. The key is random per DuckDB process, so fingerprints can't be brute-forced offline and don't compare across sessions.
- **It's pattern-based.** It will miss secrets in unusual formats, such as `mysql -pSECRET`. Treat it as protection against accidental exposure, not a guarantee.
- **Turning it off.** `SET os_redact = false` returns raw values. A harness can prevent that with `SET lock_configuration = true` after loading the extension. Redaction only protects anything if DuckDB is the agent's only way to read processes; an agent with a shell can run `ps`.

## Design notes

- **Read-only.** There are no functions that change anything.
- **Built on [`duckdb-tables`](../duckdb-tables).** Columns are declared as (name, type, description, getter), and only the columns a query selects are computed. The same declarations produce `os_describe()`.
- **Data comes from [`sysinfo`](https://crates.io/crates/sysinfo) and [`netstat2`](https://crates.io/crates/netstat2).** `sysinfo` is held at 0.38 because 0.39 needs a newer Rust than the pinned toolchain.
- **Pinned to one DuckDB version**, like the other extensions (`TARGET_DUCKDB_VERSION` in the Makefile).
- **Not yet covered:** services (launchd/systemd), installed packages, open files, and Windows.

## Development

```sh
git clone --recurse-submodules <repo>     # fetches duckdb-tables from GitHub
make configure EXTENSION_VERSION=v0.1.0   # the version is needed until the repo has a commit
make debug                                # build/debug/os.duckdb_extension
make test                                 # test/sql/os.test, against the machine running it
cargo test                                # redaction and cgroup parsing
```

The SQL tests only assert facts that hold on any macOS or Linux machine, including inside CI's Docker containers: pid 1 exists, `root` has uid 0, loopback has 127.0.0.1, and so on. So far they've been run on macOS only; Linux has been type-checked but not run. CI skips Windows, which isn't supported.
