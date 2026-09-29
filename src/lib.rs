//! `os`: the operating system as tables, for investigation. Read-only.
//!
//!   SELECT pid, name, cmdline FROM os_processes() ORDER BY rss_bytes DESC LIMIT 10;
//!   SELECT s.local_port, p.name, p.cmdline FROM os_sockets() s JOIN os_processes() p USING (pid)
//!   WHERE s.state = 'listen';
//!   SELECT * FROM os_describe() WHERE function = 'os_processes';

mod redact;
mod tables;

use duckdb_tables::{BoxError, Extension};

duckdb_tables::entrypoint!(os_init_c_api, init);

fn init(ext: &Extension) -> Result<(), BoxError> {
    ext.register_bool_setting(
        tables::REDACT_SETTING,
        true,
        "Redact secrets in os_processes command lines and os_process_env values. \
         Freeze it with SET lock_configuration = true.",
    )?;
    ext.register_describe("os_describe")?;
    ext.register::<tables::Processes>("os_processes")?;
    ext.register::<tables::ProcessEnv>("os_process_env")?;
    ext.register::<tables::Sockets>("os_sockets")?;
    ext.register::<tables::UsersTable>("os_users")?;
    ext.register::<tables::DisksTable>("os_disks")?;
    ext.register::<tables::Interfaces>("os_interfaces")?;
    ext.register::<tables::SystemTable>("os_system")?;
    Ok(())
}
