//! Process protections that the helper applies before it reads a request.
//!
//! - Linux: no core dump (`RLIMIT_CORE` 0) and not dumpable (`PR_SET_DUMPABLE` 0), which also stops a process of the
//!   same user from attaching a debugger.
//! - Windows: no error dialog and no Windows Error Reporting prompt on a crash (`SetErrorMode`).
//! - Everywhere: a panic writes a fixed line, never its message (a message could quote data).

pub fn apply() {
    platform();
    std::panic::set_hook(Box::new(|_| {
        // (stderr goes to the browser's log: a fixed text only)
        eprintln!("wren-vault: internal error");
    }));
}

#[cfg(target_os = "linux")]
fn platform() {
    // SAFETY: plain system calls with valid arguments; they change only this process.
    unsafe {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

#[cfg(windows)]
fn platform() {
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }
    // SAFETY: SetErrorMode only sets a flag of this process.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn platform() {}
