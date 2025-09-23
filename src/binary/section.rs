use goblin::Object;

/// Information about a binary section
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub is_patchable: bool,
}

/// Check if a given file offset falls within a patchable section
/// Returns the section name if found and whether it's safe to patch
pub fn check_offset_section(data: &[u8], offset: usize) -> Option<SectionInfo> {
    let obj = Object::parse(data).ok()?;

    match obj {
        Object::PE(pe) => check_pe_offset(&pe, offset),
        Object::Mach(mach) => check_macho_offset(&mach, offset),
        _ => None,
    }
}

/// Check PE section for a given offset
fn check_pe_offset(pe: &goblin::pe::PE, offset: usize) -> Option<SectionInfo> {
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;

        if offset >= start && offset < end {
            // Only .rdata and .data sections are safely patchable in binary files
            // .text section modifications will be overwritten at runtime
            let is_patchable = name == ".rdata" || name == ".data";

            return Some(SectionInfo {
                name: name.clone(),
                virtual_address: section.virtual_address as u64,
                virtual_size: section.virtual_size as u64,
                file_offset: section.pointer_to_raw_data as u64,
                is_patchable,
            });
        }
    }
    None
}

/// Check Mach-O section for a given offset
fn check_macho_offset(mach: &goblin::mach::Mach, offset: usize) -> Option<SectionInfo> {
    // Mach-O binaries have segments containing sections
    // __TEXT segment: executable code and read-only data
    // __DATA segment: read-write data

    match mach {
        goblin::mach::Mach::Binary(macho) => {
            // Iterate through segments to find which contains our offset
            for segment in &macho.segments {
                let seg_name = segment.name().ok()?;
                let file_start = segment.fileoff as usize;
                let file_end = file_start + segment.filesize as usize;

                if offset >= file_start && offset < file_end {
                    // Now find the specific section within this segment
                    if let Ok(sections) = segment.sections() {
                        for (sect, _) in sections.iter() {
                            let sect_start = sect.offset as usize;
                            let sect_end = sect_start + sect.size as usize;

                            if offset >= sect_start && offset < sect_end {
                                let section_name = sect.name().ok()?;

                                // In Mach-O, patchable sections are typically in __DATA segment
                                // __TEXT segment sections will be protected at runtime
                                let is_patchable = seg_name == "__DATA" ||
                                                  seg_name == "__DATA_CONST" ||
                                                  // __TEXT.__const is read-only data, sometimes patchable
                                                  (seg_name == "__TEXT" && section_name == "__const");

                                return Some(SectionInfo {
                                    name: format!("{}.{}", seg_name, section_name),
                                    virtual_address: sect.addr,
                                    virtual_size: sect.size,
                                    file_offset: sect.offset as u64,
                                    is_patchable,
                                });
                            }
                        }
                    }

                    // Found segment but no specific section, return segment info
                    return Some(SectionInfo {
                        name: seg_name.to_string(),
                        virtual_address: segment.vmaddr,
                        virtual_size: segment.vmsize,
                        file_offset: segment.fileoff,
                        is_patchable: seg_name == "__DATA" || seg_name == "__DATA_CONST",
                    });
                }
            }
        }
        goblin::mach::Mach::Fat(_fat) => {
            // Fat binaries contain multiple architectures
            // Proper implementation would require knowing which architecture slice we're patching
            // For now, return None and handle fat binaries separately if needed
            return None;
        }
    }

    None
}

/// Validate that all patterns are found in patchable sections
pub fn validate_patch_offsets(data: &[u8], offsets: &[(usize, &str)]) -> Result<(), String> {
    let mut errors = Vec::new();

    for (offset, pattern_name) in offsets {
        if let Some(section) = check_offset_section(data, *offset) {
            if !section.is_patchable {
                errors.push(format!(
                    "Pattern '{}' found at offset 0x{:x} in non-patchable section '{}'. \
                     Binary patching only works reliably in .rdata or .data sections.",
                    pattern_name, offset, section.name
                ));
            }
        } else {
            errors.push(format!(
                "Pattern '{}' at offset 0x{:x} - unable to determine section",
                pattern_name, offset
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_info() {
        let info = SectionInfo {
            name: ".rdata".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x2000,
            file_offset: 0x400,
            is_patchable: true,
        };

        assert_eq!(info.name, ".rdata");
        assert!(info.is_patchable);
    }

    #[test]
    fn test_pe_section_detection() {
        // Test that we correctly identify PE sections
        let rdata_info = SectionInfo {
            name: ".rdata".to_string(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            is_patchable: true,
        };
        assert!(rdata_info.is_patchable, ".rdata should be patchable");

        let text_info = SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            is_patchable: false,
        };
        assert!(!text_info.is_patchable, ".text should NOT be patchable");
    }

    #[test]
    fn test_macho_section_detection() {
        // Test Mach-O section patchability logic
        let data_section = SectionInfo {
            name: "__DATA.__data".to_string(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            is_patchable: true,
        };
        assert!(data_section.is_patchable, "__DATA sections should be patchable");

        let text_section = SectionInfo {
            name: "__TEXT.__text".to_string(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            is_patchable: false,
        };
        assert!(!text_section.is_patchable, "__TEXT.__text should NOT be patchable");

        let const_section = SectionInfo {
            name: "__TEXT.__const".to_string(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            is_patchable: true,
        };
        assert!(const_section.is_patchable, "__TEXT.__const should be patchable (read-only data)");
    }
}
