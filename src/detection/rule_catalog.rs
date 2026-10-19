use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CatalogRule {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub mitre: String,
    pub source: String,
    pub condition: String,
    pub needs: String,
    pub ships_in: String,
    pub kind: String,
}

fn r(
    id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    source: &str,
    condition: &str,
    needs: &str,
    ships_in: &str,
) -> CatalogRule {
    CatalogRule {
        id: id.to_string(),
        title: title.to_string(),
        severity: severity.to_string(),
        mitre: mitre.to_string(),
        source: source.to_string(),
        condition: condition.to_string(),
        needs: needs.to_string(),
        ships_in: ships_in.to_string(),
        kind: String::from("native"),
    }
}

pub fn builtin() -> Vec<CatalogRule> {
    vec![
        r("MFT-TS-01", "Standard Information created before File Name created", "medium", "T1070.006", "$MFT $SI and $FN", "The visible creation time ($SI) is earlier than the File Name creation ($FN) by more than a few seconds. Install caches and bulk creation seconds are discounted, and a zeroed sub second, a time before the volume, a future time or an executable in a risky folder raise it to high. The size of the gap ranks it.", "$MFT", "v0.3"),
        r("MFT-TS-02", "Standard Information sub seconds all zero", "high", "T1070.006", "$MFT $SI", "All seven sub second digits of the $SI creation are zero while the File Name keeps full precision. Timestomping tools write whole seconds.", "$MFT", "v0.3"),
        r("MFT-TS-03", "Standard Information created before the volume", "medium", "T1070.006", "$MFT", "The $SI creation is earlier than the volume creation time. A file cannot predate the file system it lives on.", "$MFT", "v0.3"),
        r("MFT-TS-05", "Standard Information creation zeroed to 1601", "medium", "T1070.006", "$MFT $SI", "The $SI creation is set to 1601-01-01, the zero value. Wipers such as Eraser leave this trace.", "$MFT", "v0.3"),
        r("MFT-TS-06", "Standard Information creation in the future", "medium", "T1070.006", "$MFT $SI", "The $SI creation is later than the analysis time. The time was set forward.", "$MFT", "v0.3"),
        r("MFT-TS-07", "File Name created before Standard Information created", "low", "T1070.006", "$MFT $SI and $FN", "The File Name creation is earlier than the $SI creation, the FN<SI direction. The File Name copy is normally set at creation, so this gap means a creation time was changed.", "$MFT", "v0.7"),
        r("MFT-AF-01", "Alternate data stream present", "low", "T1564.004", "$MFT named $DATA", "A record carries a named data stream. Extra weight for executable content and streams outside Downloads.", "$MFT", "v0.3"),
        r("MFT-AF-03", "Orphan record", "low", "T1070.004", "$MFT header", "The parent record is gone or its sequence does not match, so the full path cannot be trusted.", "$MFT", "v0.3"),
        r("MFT-AF-04", "Known wiper trace", "high", "T1070", "$MFT name", "The name matches a wiper pattern such as cipher, BCWipe or SDelete leftovers.", "$MFT", "v0.3"),
        r("MFT-AN-01", "Executable in an unusual location", "medium", "T1036.005", "$MFT path", "An executable or script sits in a temporary, recycle or drive root folder where code does not normally run.", "$MFT", "v0.3"),
        r("MFT-AN-02", "Archive in an unusual location", "low", "T1036.005", "$MFT path", "An archive sits in a temporary or root folder, possible staging for collection or exfiltration.", "$MFT", "v0.3"),
        r("MFT-AN-03", "Modified time older than creation time", "medium", "T1570", "$MFT $SI", "The content modified time is older than the creation time, so the file was copied in from another volume or the network and the creation time is the copy time.", "$MFT", "v0.3"),
        r("MFT-AN-04", "Creation burst", "low", "T1036.005", "$MFT $SI", "Many files share one creation second, which can mark an install, an unpack or staged files.", "$MFT", "v0.3"),
        r("MFT-AN-05", "Look alike system name", "high", "T1036.005", "$MFT $FN", "The name imitates a Windows system process but is spelled differently or does not exist on modern Windows.", "$MFT", "v0.3"),
        r("MFT-AN-06", "Known file from an unknown path", "high", "T1036.005", "$MFT $FN and path", "A name that matches a known Windows system file or DLL runs from a path that is not one of its homes, which catches a renamed payload hiding in plain sight.", "$MFT + known location map", "v0.7"),
        r("MFT-AN-07", "Name abuse", "high", "T1036.002", "$MFT $FN", "A right to left override character, a trailing dot or space, or a double extension in the name, all used to make a file look like a safe type.", "$MFT", "v0.7"),
        r("MFT-AN-08", "Short name does not match the long name", "low", "T1036", "$MFT $FN DOS name", "The 8.3 short name does not derive from the long name, so it is left over from an earlier name on the same record.", "$MFT", "v0.7"),
        r("MFT-AN-10", "Executable content resident in the MFT", "medium", "T1564.004", "$MFT resident $DATA", "A data stream held inside the record starts with the MZ header of a Windows executable, so code hides with no file on disk.", "$MFT", "v0.7"),
        r("MFT-AN-11", "MFT slot reused", "low", "T1070.004", "$MFT header", "An in use record with a sequence number above one, so the slot held earlier files that were deleted and the slot reused.", "$MFT", "v0.7"),
        r("MFT-AN-12", "Hidden and system executable", "medium", "T1564.001", "$MFT $SI flags", "An executable with both the hidden and system attributes set in a user writable folder, which normal software rarely does.", "$MFT", "v0.7"),
        r("MFT-RP-01", "Risky reparse point", "medium", "T1574", "$MFT reparse point", "A junction or symlink in a user writable folder that points into a system path, which can redirect a trusted path to attacker content.", "$MFT", "v0.7"),
        r("MFT-OWN-01", "System binary owned by a non-system account", "high", "T1222", "$MFT security id + $Secure", "An executable in a protected system folder whose owner, resolved through $Secure, is not SYSTEM, TrustedInstaller or Administrators. A user-owned file in a system path can mean a planted or replaced binary. Needs a $Secure in the case.", "$MFT + $Secure", "v0.8"),
        r("MFT-C1", "Timestomped file, high confidence", "high", "T1070.006", "combination", "MFT-TS-01 and MFT-TS-02 on the same file, the created before File Name gap together with zeroed sub seconds.", "$MFT", "v0.7"),
        r("MFT-C2", "Masqueraded and hidden binary", "high", "T1036.005", "combination", "MFT-AN-06 and MFT-AN-12 on the same file, a known name from a wrong path that is also hidden and system.", "$MFT", "v0.7"),
        r("MFT-C3", "Masqueraded and timestomped", "high", "T1036.005", "combination", "MFT-AN-06 and MFT-TS-02 on the same file, a known name from a wrong path with zeroed sub seconds.", "$MFT", "v0.7"),
    ]
}
