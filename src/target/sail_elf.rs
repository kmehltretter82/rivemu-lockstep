//! Minimal ELF64 image construction for the Sail RISC-V target.
//!
//! Sail's executable loader needs an ELF even though the RISU harness already
//! has all of its image fragments as byte slices.  This module deliberately
//! emits only what that loader needs: one executable `PT_LOAD` segment and no
//! section table.

use std::fmt;

/// File offset and alignment of the single loadable segment.
pub const LOAD_OFFSET: u64 = 0x1000;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const EM_RISCV: u16 = 243;
const EF_RISCV_RVC: u32 = 0x0001;
const EF_RISCV_FLOAT_ABI_DOUBLE: u32 = 0x0004;

/// Guest addresses used to place the RISU image fragments.
///
/// `code_base` is the virtual/physical base of the sole `PT_LOAD` segment.
/// `entry_addr` selects either generated code or a bootstrap as the ELF entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SailElfLayout {
    pub code_base: u64,
    pub entry_addr: u64,
    pub code_addr: u64,
    pub trap_addr: u64,
    pub bootstrap_addr: u64,
    pub scratch_addr: u64,
    pub vm_setup_addr: u64,
}

/// Error returned when an image layout cannot be represented safely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SailElfError {
    /// The load address does not meet the ELF segment alignment requirement.
    MisalignedCodeBase { code_base: u64 },
    /// A non-empty region begins below the load segment.
    RegionBelowCodeBase {
        region: &'static str,
        address: u64,
        code_base: u64,
    },
    /// Adding a region's length to its guest address overflowed `u64`.
    RegionRangeOverflow {
        region: &'static str,
        address: u64,
        length: usize,
    },
    /// Two non-empty input regions overlap in guest memory.
    OverlappingRegions {
        first: &'static str,
        second: &'static str,
    },
    /// No non-empty region contains the ELF entry point.
    EntryNotMapped { entry: u64 },
    /// The resulting file length cannot be represented on this host.
    ImageTooLarge { load_size: u64 },
    /// The host could not reserve enough memory for the output image.
    AllocationFailed { file_size: usize },
}

impl fmt::Display for SailElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MisalignedCodeBase { code_base } => write!(
                f,
                "ELF code base {code_base:#x} is not aligned to {LOAD_OFFSET:#x}"
            ),
            Self::RegionBelowCodeBase {
                region,
                address,
                code_base,
            } => write!(
                f,
                "{region} starts at {address:#x}, below ELF code base {code_base:#x}"
            ),
            Self::RegionRangeOverflow {
                region,
                address,
                length,
            } => write!(
                f,
                "{region} range overflows: address={address:#x}, length={length:#x}"
            ),
            Self::OverlappingRegions { first, second } => {
                write!(f, "ELF regions {first} and {second} overlap")
            }
            Self::EntryNotMapped { entry } => {
                write!(
                    f,
                    "ELF entry point {entry:#x} is not covered by an input region"
                )
            }
            Self::ImageTooLarge { load_size } => {
                write!(f, "ELF load image of {load_size:#x} bytes is too large")
            }
            Self::AllocationFailed { file_size } => {
                write!(f, "could not allocate {file_size:#x} bytes for ELF image")
            }
        }
    }
}

impl std::error::Error for SailElfError {}

#[derive(Clone, Copy)]
struct Region<'a> {
    name: &'static str,
    address: u64,
    bytes: &'a [u8],
    end: u64,
}

/// Builds a sectionless ELF64 little-endian RISC-V executable for Sail.
///
/// The returned image has one read/write/execute `PT_LOAD` segment at
/// `layout.code_base`, stored at file offset `0x1000` with `0x1000`
/// alignment. Its entry point is `layout.entry_addr`; its RISC-V ELF flags
/// advertise compressed instructions and the double-precision floating-point
/// ABI.  Gaps between the supplied regions are zero-filled.
pub fn build_sail_elf(
    layout: SailElfLayout,
    code: &[u8],
    trap_handler: &[u8],
    bootstrap: &[u8],
    scratch: &[u8],
    vm_setup: &[u8],
) -> Result<Vec<u8>, SailElfError> {
    if layout.code_base % LOAD_OFFSET != 0 {
        return Err(SailElfError::MisalignedCodeBase {
            code_base: layout.code_base,
        });
    }

    let mut regions = [
        make_region("code", layout.code_addr, code)?,
        make_region("trap handler", layout.trap_addr, trap_handler)?,
        make_region("bootstrap", layout.bootstrap_addr, bootstrap)?,
        make_region("scratch", layout.scratch_addr, scratch)?,
        make_region("VM setup", layout.vm_setup_addr, vm_setup)?,
    ];

    for region in regions.iter().filter(|region| !region.bytes.is_empty()) {
        if region.address < layout.code_base {
            return Err(SailElfError::RegionBelowCodeBase {
                region: region.name,
                address: region.address,
                code_base: layout.code_base,
            });
        }
    }

    regions.sort_unstable_by_key(|region| region.address);
    let nonempty: Vec<_> = regions
        .iter()
        .copied()
        .filter(|region| !region.bytes.is_empty())
        .collect();

    if !nonempty
        .iter()
        .any(|region| region.address <= layout.entry_addr && layout.entry_addr < region.end)
    {
        return Err(SailElfError::EntryNotMapped {
            entry: layout.entry_addr,
        });
    }

    for pair in nonempty.windows(2) {
        if pair[1].address < pair[0].end {
            return Err(SailElfError::OverlappingRegions {
                first: pair[0].name,
                second: pair[1].name,
            });
        }
    }

    let load_end = nonempty
        .iter()
        .map(|region| region.end)
        .max()
        .expect("the entry-point check guarantees a non-empty region");
    let load_size = load_end - layout.code_base;
    let file_size_u64 = LOAD_OFFSET
        .checked_add(load_size)
        .ok_or(SailElfError::ImageTooLarge { load_size })?;
    let file_size =
        usize::try_from(file_size_u64).map_err(|_| SailElfError::ImageTooLarge { load_size })?;

    let mut elf = Vec::new();
    elf.try_reserve_exact(file_size)
        .map_err(|_| SailElfError::AllocationFailed { file_size })?;
    elf.resize(file_size, 0);

    write_elf_header(&mut elf[..ELF_HEADER_SIZE], layout.entry_addr);
    write_program_header(
        &mut elf[ELF_HEADER_SIZE..ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE],
        layout.code_base,
        load_size,
    );

    for region in nonempty {
        let relative = region.address - layout.code_base;
        let file_offset_u64 = LOAD_OFFSET
            .checked_add(relative)
            .ok_or(SailElfError::ImageTooLarge { load_size })?;
        let file_offset = usize::try_from(file_offset_u64)
            .map_err(|_| SailElfError::ImageTooLarge { load_size })?;
        let file_end = file_offset
            .checked_add(region.bytes.len())
            .ok_or(SailElfError::ImageTooLarge { load_size })?;
        elf[file_offset..file_end].copy_from_slice(region.bytes);
    }

    Ok(elf)
}

fn make_region<'a>(
    name: &'static str,
    address: u64,
    bytes: &'a [u8],
) -> Result<Region<'a>, SailElfError> {
    let length = u64::try_from(bytes.len()).map_err(|_| SailElfError::RegionRangeOverflow {
        region: name,
        address,
        length: bytes.len(),
    })?;
    let end = address
        .checked_add(length)
        .ok_or(SailElfError::RegionRangeOverflow {
            region: name,
            address,
            length: bytes.len(),
        })?;
    Ok(Region {
        name,
        address,
        bytes,
        end,
    })
}

fn write_elf_header(header: &mut [u8], entry: u64) {
    header[0..4].copy_from_slice(b"\x7fELF");
    header[4] = 2; // ELFCLASS64
    header[5] = 1; // ELFDATA2LSB
    header[6] = 1; // EV_CURRENT
    header[7] = 0; // ELFOSABI_NONE
    put_u16(header, 16, 2); // ET_EXEC
    put_u16(header, 18, EM_RISCV);
    put_u32(header, 20, 1); // EV_CURRENT
    put_u64(header, 24, entry);
    put_u64(header, 32, ELF_HEADER_SIZE as u64);
    put_u64(header, 40, 0); // No section table.
    put_u32(header, 48, EF_RISCV_RVC | EF_RISCV_FLOAT_ABI_DOUBLE);
    put_u16(header, 52, ELF_HEADER_SIZE as u16);
    put_u16(header, 54, PROGRAM_HEADER_SIZE as u16);
    put_u16(header, 56, 1);
    put_u16(header, 58, 0);
    put_u16(header, 60, 0);
    put_u16(header, 62, 0);
}

fn write_program_header(header: &mut [u8], load_addr: u64, load_size: u64) {
    put_u32(header, 0, 1); // PT_LOAD
    put_u32(header, 4, 0x7); // PF_R | PF_W | PF_X
    put_u64(header, 8, LOAD_OFFSET);
    put_u64(header, 16, load_addr);
    put_u64(header, 24, load_addr);
    put_u64(header, 32, load_size);
    put_u64(header, 40, load_size);
    put_u64(header, 48, LOAD_OFFSET);
}

fn put_u16(dst: &mut [u8], offset: usize, value: u16) {
    dst[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(dst: &mut [u8], offset: usize, value: u32) {
    dst[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(dst: &mut [u8], offset: usize, value: u64) {
    dst[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE_BASE: u64 = 0x8000_0000;

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn fixture_layout() -> SailElfLayout {
        SailElfLayout {
            code_base: CODE_BASE,
            entry_addr: CODE_BASE,
            code_addr: CODE_BASE,
            bootstrap_addr: CODE_BASE + 0x1000,
            trap_addr: CODE_BASE + 0x2000,
            scratch_addr: CODE_BASE + 0x10_000,
            vm_setup_addr: CODE_BASE + 0x11_000,
        }
    }

    #[test]
    fn emits_expected_elf_and_program_headers() {
        let elf = build_sail_elf(
            fixture_layout(),
            &[0x13, 0, 0, 0],
            &[0x73, 0, 0, 0],
            &[0x6f, 0, 0, 0],
            &[0xaa, 0xbb, 0xcc],
            &[],
        )
        .unwrap();

        assert_eq!(&elf[0..4], b"\x7fELF");
        assert_eq!(elf[4], 2);
        assert_eq!(elf[5], 1);
        assert_eq!(elf[6], 1);
        assert_eq!(u16_at(&elf, 16), 2);
        assert_eq!(u16_at(&elf, 18), EM_RISCV);
        assert_eq!(u32_at(&elf, 20), 1);
        assert_eq!(u64_at(&elf, 24), CODE_BASE);
        assert_eq!(u64_at(&elf, 32), ELF_HEADER_SIZE as u64);
        assert_eq!(u64_at(&elf, 40), 0);
        assert_eq!(u32_at(&elf, 48), 0x5);
        assert_eq!(u16_at(&elf, 52), ELF_HEADER_SIZE as u16);
        assert_eq!(u16_at(&elf, 54), PROGRAM_HEADER_SIZE as u16);
        assert_eq!(u16_at(&elf, 56), 1);
        assert_eq!(u16_at(&elf, 60), 0);

        let ph = ELF_HEADER_SIZE;
        let load_size = 0x10_003;
        assert_eq!(u32_at(&elf, ph), 1);
        assert_eq!(u32_at(&elf, ph + 4), 0x7);
        assert_eq!(u64_at(&elf, ph + 8), LOAD_OFFSET);
        assert_eq!(u64_at(&elf, ph + 16), CODE_BASE);
        assert_eq!(u64_at(&elf, ph + 24), CODE_BASE);
        assert_eq!(u64_at(&elf, ph + 32), load_size);
        assert_eq!(u64_at(&elf, ph + 40), load_size);
        assert_eq!(u64_at(&elf, ph + 48), LOAD_OFFSET);
        assert_eq!(elf.len(), LOAD_OFFSET as usize + load_size as usize);
    }

    #[test]
    fn places_each_region_at_its_exact_guest_offset() {
        let layout = fixture_layout();
        let code = [1, 2, 3, 4, 5];
        let trap = [6, 7, 8];
        let bootstrap = [9, 10, 11, 12];
        let scratch = [13, 14, 15, 16, 17, 18];
        let vm_setup = [19, 20, 21, 22];
        let elf = build_sail_elf(layout, &code, &trap, &bootstrap, &scratch, &vm_setup).unwrap();

        for (address, expected) in [
            (layout.code_addr, code.as_slice()),
            (layout.trap_addr, trap.as_slice()),
            (layout.bootstrap_addr, bootstrap.as_slice()),
            (layout.scratch_addr, scratch.as_slice()),
            (layout.vm_setup_addr, vm_setup.as_slice()),
        ] {
            let offset = (LOAD_OFFSET + address - layout.code_base) as usize;
            assert_eq!(&elf[offset..offset + expected.len()], expected);
        }

        assert!(
            elf[LOAD_OFFSET as usize + code.len()..0x2000]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn accepts_bootstrap_as_the_entry_region() {
        let mut layout = fixture_layout();
        layout.entry_addr = layout.bootstrap_addr;

        let elf = build_sail_elf(layout, &[1], &[2], &[3], &[4], &[]).unwrap();
        assert_eq!(u64_at(&elf, 24), layout.bootstrap_addr);
        assert_eq!(elf[LOAD_OFFSET as usize], 1);
        assert_eq!(elf[LOAD_OFFSET as usize + 0x1000], 3);
    }

    #[test]
    fn rejects_overlapping_regions() {
        let mut layout = fixture_layout();
        layout.bootstrap_addr = CODE_BASE + 2;

        let error = build_sail_elf(layout, &[1, 2, 3, 4], &[5], &[6, 7], &[8], &[])
            .expect_err("code and bootstrap overlap");
        assert_eq!(
            error,
            SailElfError::OverlappingRegions {
                first: "code",
                second: "bootstrap",
            }
        );
    }

    #[test]
    fn rejects_unmapped_entry_and_invalid_ranges() {
        let mut layout = fixture_layout();
        layout.entry_addr += 4;
        assert_eq!(
            build_sail_elf(layout, &[1], &[2], &[3], &[4], &[]).unwrap_err(),
            SailElfError::EntryNotMapped {
                entry: CODE_BASE + 4
            }
        );

        layout.entry_addr = CODE_BASE;
        layout.scratch_addr = u64::MAX;
        assert_eq!(
            build_sail_elf(layout, &[1], &[2], &[3], &[4], &[]).unwrap_err(),
            SailElfError::RegionRangeOverflow {
                region: "scratch",
                address: u64::MAX,
                length: 1,
            }
        );
    }
}
