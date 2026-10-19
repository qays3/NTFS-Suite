pub fn open(url: &str) {
    let _ = try_open(url);
}

#[cfg(target_os = "windows")]
fn try_open(url: &str) -> std::io::Result<()> {
    std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn()
        .map(|_| ())
}

#[cfg(target_os = "linux")]
fn try_open(url: &str) -> std::io::Result<()> {
    std::process::Command::new("xdg-open").arg(url).spawn().map(|_| ())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn try_open(_url: &str) -> std::io::Result<()> {
    Ok(())
}
