//! What names this boot of the computer: an unlock remembered "until the computer restarts" keeps it, and one kept in
//! another boot is no longer taken (sdk.rs, `unlock_remembered`). "" when the system does not say.

/// Linux: the kernel's random identifier of this boot. Blocks (a file read): call it on a blocking thread.
#[cfg(target_os = "linux")]
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Windows: the minute the computer started (now less the time since the boot), so that the same boot gives the same
/// text whenever it is asked.
#[cfg(windows)]
pub fn boot_id() -> String {
    let since_boot_ms = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if now == 0 {
        return String::new();
    }
    // (a minute's rounding: the two reads are not at the same instant)
    format!("boot-{}", (now.saturating_sub(since_boot_ms) + 30_000) / 60_000)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn boot_id() -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_same_boot_gives_the_same_name() {
        let a = super::boot_id();
        assert_eq!(a, super::boot_id());
        #[cfg(any(target_os = "linux", windows))]
        assert!(!a.is_empty(), "this system says when it started");
    }
}
