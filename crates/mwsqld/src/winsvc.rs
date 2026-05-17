//! Windows Service Control Manager integration.
//!
//! SCM launches `mwsqld service`; that calls [`run`], which hands control
//! to the SCM dispatcher. The control handler maps STOP/SHUTDOWN to a
//! broadcast that drives `Daemon::run`'s graceful exit, exactly like Ctrl-C
//! does in the interactive `run` path.
//!
//! Service mode always uses the file keystore under the platform state dir
//! (a virtual service account has no usable DPAPI profile — see
//! `mwsqlctl::installer` for the rationale).

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Result;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "mwsqld";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Entry point for the hidden `service` subcommand. Blocks until SCM stops
/// the service.
pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("mwsqld service error: {e:#}");
    }
}

fn report(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accept: ServiceControlAccept,
    checkpoint: u32,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;

    report(&status, ServiceState::StartPending, ServiceControlAccept::empty(), 1)?;

    let state_dir = crate::default_state_dir();
    let ks = crate::KeystoreChoice::default_file(&state_dir);

    // Own the global subscriber/audit guard for the service lifetime.
    let _audit = crate::install_audit(&state_dir)?;

    let rt = tokio::runtime::Runtime::new()?;
    let serve_result = rt.block_on(async {
        let cfg = crate::load_config(&state_dir, &ks)?;
        // Service mode is non-interactive: never accept an unpinned host key.
        let daemon = crate::Daemon::bind(state_dir.clone(), &cfg, "127.0.0.1", false).await?;

        let (tx, rx) = tokio::sync::broadcast::channel(1);
        // Bridge the blocking std mpsc from the SCM control handler into the
        // async broadcast the daemon understands.
        std::thread::spawn(move || {
            let _ = shutdown_rx.recv();
            let _ = tx.send(());
        });

        report(&status, ServiceState::Running,
               ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0)?;
        daemon.run(rx).await
    });

    report(&status, ServiceState::StopPending, ServiceControlAccept::empty(), 1)?;
    report(&status, ServiceState::Stopped, ServiceControlAccept::empty(), 0)?;
    serve_result
}
