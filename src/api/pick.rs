use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct PickRequest {
    #[serde(default)]
    pub kind: String,
}

#[derive(Serialize)]
pub struct PickResponse {
    pub path: Option<String>,
    pub supported: bool,
}

pub fn pick(request: &PickRequest) -> PickResponse {
    let want_folder = request.kind == "folder";
    match native_pick(want_folder) {
        PickOutcome::Picked(path) => PickResponse { path: Some(path), supported: true },
        PickOutcome::Cancelled => PickResponse { path: None, supported: true },
        PickOutcome::Unsupported => PickResponse { path: None, supported: false },
    }
}

enum PickOutcome {
    Picked(String),
    Cancelled,
    Unsupported,
}

#[cfg(target_os = "windows")]
fn native_pick(want_folder: bool) -> PickOutcome {
    let script = if want_folder {
        "Add-Type -AssemblyName System.Windows.Forms; $o = New-Object System.Windows.Forms.Form; $o.TopMost = $true; $o.Opacity = 0; $o.ShowInTaskbar = $false; $o.Show(); $o.Activate(); $d = New-Object System.Windows.Forms.FolderBrowserDialog; $r = $d.ShowDialog($o); $o.Close(); if ($r -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write($d.SelectedPath) }"
    } else {
        "Add-Type -AssemblyName System.Windows.Forms; $o = New-Object System.Windows.Forms.Form; $o.TopMost = $true; $o.Opacity = 0; $o.ShowInTaskbar = $false; $o.Show(); $o.Activate(); $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Title = 'Select evidence file'; $d.Filter = 'All files (*.*)|*.*'; $d.CheckFileExists = $true; $r = $d.ShowDialog($o); $o.Close(); if ($r -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write($d.FileName) }"
    };
    let output = Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", script])
        .output();
    match output {
        Ok(out) => {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if path.is_empty() {
                PickOutcome::Cancelled
            } else {
                PickOutcome::Picked(path)
            }
        }
        Err(_) => PickOutcome::Unsupported,
    }
}

#[cfg(not(target_os = "windows"))]
fn native_pick(want_folder: bool) -> PickOutcome {
    let zenity = if want_folder {
        vec!["--file-selection", "--directory"]
    } else {
        vec!["--file-selection"]
    };
    if let Ok(out) = Command::new("zenity").args(&zenity).output() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return if path.is_empty() {
            PickOutcome::Cancelled
        } else {
            PickOutcome::Picked(path)
        };
    }
    PickOutcome::Unsupported
}
