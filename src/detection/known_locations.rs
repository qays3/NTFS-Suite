const SYSTEM_HOMES: &[&str] = &[
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
];

const WINDOWS_HOMES: &[&str] = &["\\windows\\"];

const SYSTEM_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "winlogon.exe",
    "smss.exe",
    "wininit.exe",
    "taskhostw.exe",
    "rundll32.exe",
    "dllhost.exe",
    "conhost.exe",
    "spoolsv.exe",
    "cmd.exe",
    "powershell.exe",
    "dwm.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "searchindexer.exe",
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "ole32.dll",
    "shell32.dll",
    "ws2_32.dll",
    "msvcrt.dll",
];

const WINDOWS_NAMES: &[&str] = &["explorer.exe"];

pub fn allowed_homes(name_lower: &str) -> Option<&'static [&'static str]> {
    if WINDOWS_NAMES.contains(&name_lower) {
        Some(WINDOWS_HOMES)
    } else if SYSTEM_NAMES.contains(&name_lower) {
        Some(SYSTEM_HOMES)
    } else {
        None
    }
}

pub fn masquerade_reason(name_lower: &str, path_lower: &str) -> Option<String> {
    let homes = allowed_homes(name_lower)?;
    if homes.iter().any(|home| path_lower.contains(home)) {
        return None;
    }
    Some(format!(
        "{} is a known Windows system file, but this copy is at a path that is not one of its homes. The real {} runs only from the Windows system folders, so a copy here is likely a renamed payload hiding in plain sight.",
        name_lower, name_lower
    ))
}
