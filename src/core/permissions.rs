/// PDF permission flags (per PDF spec, Table 22 / Table 24).
///
/// Permissions are stored as a 32-bit integer where specific bits control access.
/// Defaults to all permissions granted; user revokes with --no-print, --no-copy, --no-edit.
#[derive(Debug, Clone, Copy)]
pub struct PdfPermissions {
    pub allow_print: bool,
    pub allow_copy: bool,
    pub allow_edit: bool,
}

impl Default for PdfPermissions {
    fn default() -> Self {
        Self {
            allow_print: true,
            allow_copy: true,
            allow_edit: true,
        }
    }
}

impl PdfPermissions {
    /// Encode as the 32-bit P value for the encryption dictionary.
    pub fn to_p_value(self) -> i32 {
        let mut p: u32 = 0xFFFFF0C0; // bits 7-8 and 13-32 set

        if self.allow_print {
            p |= 1 << 2;  // bit 3: print
            p |= 1 << 11; // bit 12: high-quality print
        }
        if self.allow_edit {
            p |= 1 << 3;  // bit 4: modify
            p |= 1 << 5;  // bit 6: annotations
            p |= 1 << 8;  // bit 9: fill forms
            p |= 1 << 10; // bit 11: assemble
        }
        if self.allow_copy {
            p |= 1 << 4; // bit 5: copy
            p |= 1 << 9; // bit 10: accessibility extract
        }

        p as i32
    }

    /// Decode from the P value in the encryption dictionary.
    pub fn from_p_value(p: i32) -> Self {
        let p = p as u32;
        Self {
            allow_print: (p & (1 << 2)) != 0,
            allow_copy: (p & (1 << 4)) != 0,
            allow_edit: (p & (1 << 3)) != 0,
        }
    }
}
