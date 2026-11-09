/*
 * h_test.S: self-checking bare-metal test of the RISC-V H extension for one
 * hart of the QEMU/rivemu `virt` machine (RAM at 0x8000_0000, 16550 UART at
 * 0x1000_0000, SiFive test finisher at 0x10_0000).
 *
 * Runs on `qemu-system-riscv64 -M virt -cpu rv64,h=true,...` and on
 * `rivemu -cpu rv64,h=on`, and under `rivemu-lockstep boot-trace
 * --hypervisor`, which compares every instruction and trap with QEMU.
 * Built with -DSAIL it prints and exits through HTIF for the Sail model
 * (`sail_riscv_sim h_test_sail.elf`). It
 * prints one line per failed check ("FAIL <id> <value>") and ends with
 * "H-TEST PASS" or "H-TEST FAIL", then powers the machine off.
 *
 * M-mode drives every test: it enters HS, U, VS or VU with mret at a test
 * label, and every test ends in a trap that returns to M-mode right after
 * the `call enter_*` that started it. Results land in fixed registers:
 *   s2 mcause  s3 mtval  s4 mtval2  s5 mstatus  s11 mepc   (M handler)
 *   s6 scause  s7 stval  s8 htval   s9 hstatus  s10 sepc   (HS handler)
 *   s6 vscause s7 vstval s9 vsstatus s10 vsepc             (VS handler)
 * The HS and VS handlers end with ecall (cause 9 or 10 in s2).
 *
 * Checks follow the privileged spec. Where QEMU 11.1.3 differs from it,
 * the default build takes another path or does not look; -DSPEC adds the
 * checks for those cases (section S), for rivemu and the Sail model
 * (h_test_spec.bin, h_test_sail.elf). The QEMU differences:
 *  - QEMU cannot write mstatus.MPV (its write_mstatus mask lacks it), so
 *    VS and VU are entered from an HS trampoline with hstatus.SPV and sret,
 *    and M-mode accesses with MPRV and MPV = 1 run in a handler entered by
 *    a trap from VS-mode (which sets MPV).
 *  - mstatus.GVA on traps into M-mode: QEMU sets it whenever V = 1 and the
 *    trap value is nonzero, never with V = 0, and never clears it. Only the
 *    case where both agree (a guest-page fault from V = 1) is checked;
 *    rivemu-lockstep tolerates GVA in mstatus reads.
 *  - hvip reads in QEMU include other pending interrupts (STIP, MTIP), so
 *    the S and M timers are turned off.
 *  - QEMU also writes hstatus.GVA (with 0) on traps into VS-mode, where
 *    the spec leaves hstatus alone; the M handler clears hstatus.GVA so
 *    that this has no visible effect.
 *  - vsepc[0] is not cleared by QEMU; only even values are written.
 *  - QEMU masks a VS-mode sie read with mideleg's S-level bits, so that
 *    test delegates them (as SBI firmware does).
 *  - QEMU keeps every hstatus bit writable, reserved ones included; only
 *    the defined fields are written.
 *  - QEMU keeps the guest physical fault address until its next TLB fill,
 *    so a later trap that is not a guest-page fault could report it in
 *    htval/mtval2. The M handler flushes the TLB before returning.
 */

#define UART      0x10000000
#define TESTDEV   0x100000

#define G_ROOT    0x80010000      /* Sv39x4 root, 16 KiB */
#define G_L1      0x80014000
#define G_L0      0x80015000
#define VS_ROOT   0x80020000      /* Sv39 root, GPA == PA */
#define DATA0     0x80030000
#define DATA1     0x80031000
#define VAR       0x80032000      /* resume address */

#define VAL0      0x1122334455667788
#define VAL1      0x99aabbccddeeff00

#define SIE       (1 << 1)
#define SPIE      (1 << 5)
#define SPP       (1 << 8)
#define MPP       (3 << 11)
#define MPP_S     (1 << 11)
#define MPRV      (1 << 17)
#define SUM       (1 << 18)
#define TVM       (1 << 20)
#define GVA       (1 << 38)
#define MPV       (1 << 39)

#define H_GVA     (1 << 6)
#define H_SPV     (1 << 7)
#define H_SPVP    (1 << 8)
#define H_HU      (1 << 9)
#define H_VTVM    (1 << 20)
#define H_VTW     (1 << 21)
#define H_VTSR    (1 << 22)

#define STCE      (1 << 63)
#define CLINT_MTIMECMP 0x2004000
#define CSR_STIMECMP   0x14d
#define INTR      (1 << 63)

#define CSR_HSTATUS    0x600
#define CSR_HEDELEG    0x602
#define CSR_HIDELEG    0x603
#define CSR_HIE        0x604
#define CSR_HTIMEDELTA 0x605
#define CSR_HCOUNTEREN 0x606
#define CSR_HGEIE      0x607
#define CSR_HENVCFG    0x60a
#define CSR_HTVAL      0x643
#define CSR_HIP        0x644
#define CSR_HVIP       0x645
#define CSR_HGATP      0x680
#define CSR_VSSTATUS   0x200
#define CSR_VSIE       0x204
#define CSR_VSTVEC     0x205
#define CSR_VSSCRATCH  0x240
#define CSR_VSEPC      0x241
#define CSR_VSCAUSE    0x242
#define CSR_VSTVAL     0x243
#define CSR_VSIP       0x244
#define CSR_VSTIMECMP  0x24d
#define CSR_VSATP      0x280
#define CSR_MTVAL2     0x34b

/* A leaf or pointer PTE for physical address `pa`. */
#define PTE(pa, f)  ((((pa) >> 12) << 10) | (f))
#define LEAF_G      0xdf   /* V R W X U A D: G-stage leaves need U */
#define LEAF_G_RO   0x53   /* V R U A */
#define LEAF_VS     0xcf   /* V R W X A D (supervisor) */
#define LEAF_VS_U   0xdf   /* V R W X U A D */
#define PTR         0x01

/* Clobbers t2, t3. */
#ifdef SAIL
/* The Sail model's console: HTIF device 1, command 1. */
.macro PUTC reg
    li t3, (1 << 56) | (1 << 48)
    or t3, t3, \reg
    la t2, tohost
    sd t3, 0(t2)
.endm
#else
.macro PUTC reg
    li t2, UART
8:  lbu t3, 5(t2)
    andi t3, t3, 0x20
    beqz t3, 8b
    sb \reg, 0(t2)
.endm
#endif

/* Ends the test: code 0 passes. Clobbers t0, t1. */
.macro EXIT code
#ifdef SAIL
    la t0, tohost
    li t1, (\code << 1) | 1
    sd t1, 0(t0)
#else
    li t0, TESTDEV
.if \code == 0
    li t1, 0x5555                   /* SiFive test: pass */
.else
    li t1, (\code << 16) | 0x3333  /* fail with exit code */
.endif
    sw t1, 0(t0)
#endif
.endm

.macro RESET
    li s2, -1
    li s3, -1
    li s4, -1
    li s5, -1
    li s6, -1
    li s7, -1
    li s8, -1
    li s9, -1
    li s10, -1
    li s11, -1
.endm

/* Fails check `id` unless reg == val. Clobbers t1, a0, a6, a7, ra, s1. */
.macro CHECK reg, val, id
    li t1, \val
    beq \reg, t1, 7f
    li s1, \id
    mv a0, \reg
    call fail
7:
.endm

/* As CHECK, with the expected value in register r2. */
.macro CHECKR reg, r2, id
    beq \reg, \r2, 7f
    li s1, \id
    mv a0, \reg
    call fail
7:
.endm

/* Checks bit `bit` of reg. Clobbers a5 too. */
.macro CHECKBIT reg, bit, val, id
    srli a5, \reg, \bit
    andi a5, a5, 1
    CHECK a5, \val, \id
.endm

/* Runs `label` in `mode` (hs, u, vs, vu) until it traps back to M-mode. */
.macro ENTER mode, label
    la a0, \label
    call enter_\mode
.endm

    .option nopic                   /* la is pc-relative */
    .text
    .globl _start
_start:
    la t0, m_handler
    csrw mtvec, t0
    li s0, 0
    /* PMP: all memory for S and U. */
    li t0, -1
    csrw pmpaddr0, t0
    li t0, 0x1f
    csrw pmpcfg0, t0
    /* A fixed environment: Sstc on, no A/D updates, no double-trap. */
    li t0, STCE
    csrw menvcfg, t0
    csrw CSR_HENVCFG, zero
    li t0, -1
    csrw mcounteren, t0
    csrw scounteren, t0
    csrw CSR_HCOUNTEREN, t0
    csrw medeleg, zero
    csrw mideleg, zero
    csrw CSR_HEDELEG, zero
    csrw CSR_HIDELEG, zero
    csrw mie, zero
    li t0, -1                       /* no S or M timer interrupt pending */
    csrw CSR_STIMECMP, t0
    li t1, CLINT_MTIMECMP
    sd t0, 0(t1)
    la t0, hs_handler
    csrw stvec, t0
    la t0, vs_handler
    csrw CSR_VSTVEC, t0
    la a0, msg_start
    call puts

/* ---------------- A: CSRs from M-mode ---------------- */
    csrr t4, misa
    CHECKBIT t4, 7, 1, 0xa1
    csrr t4, mideleg                /* VS-level and SGEI always delegated */
    CHECK t4, 0x1444, 0xa2
    li t4, 0xffff
    csrw CSR_HIDELEG, t4
    csrr t4, CSR_HIDELEG
    CHECK t4, 0x444, 0xa3
    csrw CSR_HIDELEG, zero
    li t4, -1
    csrw CSR_HEDELEG, t4
    csrr t4, CSR_HEDELEG            /* 0-8, 12, 13, 15, 18 */
    li t5, ~(1 << 19)               /* 19 (hardware error): Sail has it */
    and t4, t4, t5
    CHECK t4, 0x4b1ff, 0xa4
    csrw CSR_HEDELEG, zero
    li t4, -1
    csrw medeleg, t4
    csrr t4, medeleg                /* plus 9, 10 and 20-23 */
    li t5, ~(1 << 19)
    and t4, t4, t5
    CHECK t4, 0xf4b7ff, 0xa5
    csrw medeleg, zero
    /* The defined fields only: QEMU keeps reserved hstatus bits. */
    li t4, H_GVA | H_SPV | H_SPVP | H_HU | H_VTVM | H_VTW | H_VTSR | (1 << 32)
    csrw CSR_HSTATUS, t4
    csrr t4, CSR_HSTATUS
    srli t5, t4, 32
    andi t5, t5, 3
    CHECK t5, 2, 0xa6               /* VSXL = 64 */
    csrw CSR_HSTATUS, zero
    li t4, -1
    csrw CSR_HVIP, t4
    csrr t4, CSR_HVIP
    CHECK t4, 0x444, 0xa7
    csrw CSR_HVIP, zero
    li t4, 4
    csrw CSR_HIP, t4                /* hip.VSSIP is hvip.VSSIP */
    csrr t4, CSR_HVIP
    CHECK t4, 4, 0xa8
    csrw CSR_HIP, zero
    li t4, -1
    csrw CSR_HIE, t4
    csrr t4, CSR_HIE                /* VS bits and SGEIE (GEILEN = 0: 0) */
    andi t4, t4, 0x444
    CHECK t4, 0x444, 0xa9
    csrw CSR_HIE, zero
    li t4, 0x1234
    csrw CSR_VSEPC, t4
    csrr t4, CSR_VSEPC
    CHECK t4, 0x1234, 0xaa
    li t4, (9 << 60) | 5
    csrw CSR_VSATP, t4
    li t4, (1 << 60) | 7            /* reserved mode: ignored */
    csrw CSR_VSATP, t4
    csrr t4, CSR_VSATP
    CHECK t4, (9 << 60) | 5, 0xab
    csrw CSR_VSATP, zero
    li t4, (8 << 60) | (0x3fff << 44) | (G_ROOT >> 12)
    csrw CSR_HGATP, t4
    csrr t5, CSR_HGATP
    CHECKR t5, t4, 0xac
    csrw CSR_HGATP, zero
    li t4, 123
    csrw CSR_HTIMEDELTA, t4
    csrr t4, CSR_HTIMEDELTA
    CHECK t4, 123, 0xae
    csrw CSR_HTIMEDELTA, zero
    li t4, 0x222
    csrw CSR_VSIE, t4               /* no VS bits delegated: reads 0 */
    csrr t4, CSR_VSIE
    CHECK t4, 0, 0xaf

/* ---------------- B: VS and VU with both stages Bare ---------------- */
    li t0, 0x5678
    csrw sscratch, t0
    li t0, 0x1234
    csrw CSR_VSSCRATCH, t0
    li t0, SUM
    csrw CSR_VSSTATUS, t0
    RESET
    ENTER vs, vs_b1
    CHECK s2, 10, 0xb1              /* ecall from VS */
    la t4, vs_b1_ecall
    CHECKR s11, t4, 0xb2
    CHECKBIT s5, 39, 1, 0xb3        /* MPV */
    srli t4, s5, 11
    andi t4, t4, 3
    CHECK t4, 1, 0xb4               /* MPP = S */
    CHECK a1, 0x1234, 0xb5          /* VS sscratch is vsscratch */
    CHECKBIT a2, 18, 1, 0xb6        /* VS sstatus is vsstatus */
    csrr t4, sscratch
    CHECK t4, 0x5678, 0xb7          /* HS sscratch untouched */
    csrr t4, CSR_VSSCRATCH
    CHECK t4, 0x4321, 0xb8          /* VS wrote vsscratch */
    csrr t4, mstatus
    CHECKBIT t4, 18, 0, 0xb9        /* HS SUM untouched */

    /* Virtual-instruction exceptions (22) from VS-mode. */
    RESET
    ENTER vs, vs_hstatus
    CHECK s2, 22, 0xba
    RESET
    ENTER vs, vs_vsstatus
    CHECK s2, 22, 0xbb
    RESET
    ENTER vs, vs_hfence
    CHECK s2, 22, 0xbc
    RESET
    ENTER vs, vs_hlv
    CHECK s2, 22, 0xbd
    /* An M-level CSR from VS-mode is illegal (2). */
    RESET
    ENTER vs, vs_mhartid
    CHECK s2, 2, 0xbe
    li t0, H_VTVM
    csrw CSR_HSTATUS, t0
    RESET
    ENTER vs, vs_satp
    CHECK s2, 22, 0xbf
    RESET
    ENTER vs, vs_sfence
    CHECK s2, 22, 0xc0
    li t0, H_VTW
    csrw CSR_HSTATUS, t0
    RESET
    ENTER vs, vs_wfi
    CHECK s2, 22, 0xc1
    li t0, H_VTSR
    csrw CSR_HSTATUS, t0
    RESET
    ENTER vs, vs_sret
    CHECK s2, 22, 0xc2
    csrw CSR_HSTATUS, zero
    RESET
    ENTER vs, vs_satp               /* VTVM = 0: allowed */
    CHECK s2, 10, 0xc3

    /* VU-mode. */
    RESET
    ENTER vu, vu_sstatus            /* S CSR from VU: virtual instruction */
    CHECK s2, 22, 0xc4
    RESET
    ENTER vu, vu_wfi                /* TW = 0: virtual instruction */
    CHECK s2, 22, 0xc5
    RESET
    ENTER vu, vu_ecall              /* not delegated: M */
    CHECK s2, 8, 0xc6
    CHECKBIT s5, 39, 1, 0xc7
    li t0, 1 << 8
    csrw medeleg, t0                /* to HS */
    RESET
    ENTER vu, vu_ecall
    CHECK s2, 9, 0xc8
    CHECK s6, 8, 0xc9
    CHECKBIT s9, 7, 1, 0xca         /* SPV */
    CHECKBIT s9, 8, 0, 0xcb         /* SPVP: from VU */
    la t4, vu_ecall
    CHECKR s10, t4, 0xcc
    li t0, 1 << 8
    csrw CSR_HEDELEG, t0            /* to VS */
    RESET
    ENTER vu, vu_ecall
    CHECK s2, 10, 0xcd
    CHECK s6, 8, 0xce
    CHECKR s10, t4, 0xcf
    CHECKBIT s9, 8, 0, 0xd0         /* vsstatus.SPP = U */
    csrw medeleg, zero
    csrw CSR_HEDELEG, zero
    /* Counter access from VU: hcounteren and scounteren. */
    li t0, ~2
    csrw scounteren, t0
    RESET
    ENTER vu, vu_rdtime
    CHECK s2, 22, 0xd1
    li t0, -1
    csrw scounteren, t0
    li t0, ~2
    csrw CSR_HCOUNTEREN, t0
    RESET
    ENTER vs, vs_rdtime
    CHECK s2, 22, 0xd2
    li t0, -1
    csrw CSR_HCOUNTEREN, t0
    /* htimedelta offsets VS time. */
    li t0, 0x10000000
    csrw CSR_HTIMEDELTA, t0
    rdtime a3
    RESET
    ENTER vs, vs_rdtime
    CHECK s2, 10, 0xd3
    sub t4, a0, a3
    li t5, 0x10000000
    bgeu t4, t5, 1f
    li s1, 0xd4
    mv a0, t4
    call fail
1:  csrw CSR_HTIMEDELTA, zero

    /* Illegal instruction from VS delegated to HS, then to VS. */
    li t0, 1 << 2
    csrw medeleg, t0
    RESET
    ENTER vs, vs_mhartid
    CHECK s2, 9, 0xd5
    CHECK s6, 2, 0xd6
    lwu t4, vs_mhartid
    CHECKR s7, t4, 0xd7             /* stval: the instruction */
    CHECKBIT s9, 7, 1, 0xd8         /* SPV */
    CHECKBIT s9, 8, 1, 0xd9         /* SPVP: from VS */
    CHECKBIT s9, 6, 0, 0xda         /* GVA */
    CHECK s8, 0, 0xdb               /* htval */
    li t0, 1 << 2
    csrw CSR_HEDELEG, t0
    RESET
    ENTER vs, vs_mhartid
    CHECK s2, 10, 0xdc
    CHECK s6, 2, 0xdd
    CHECKR s7, t4, 0xde
    csrw medeleg, zero
    csrw CSR_HEDELEG, zero

/* ---------------- C: two-stage translation ---------------- */
    li t0, G_ROOT
    li t1, VS_ROOT + 0x1000
1:  sd zero, 0(t0)
    addi t0, t0, 8
    bltu t0, t1, 1b
    li t0, G_ROOT
    li t1, PTE(0x80000000, LEAF_G)
    sd t1, 2*8(t0)                  /* GPA 2-3 GiB -> PA 2-3 GiB */
    li t1, PTE(0x80000000, LEAF_G_RO)
    sd t1, 4*8(t0)                  /* GPA 4-5 GiB -> PA 2-3 GiB, read-only */
    li t1, PTE(G_L1, PTR)
    sd t1, 5*8(t0)                  /* GPA 5-6 GiB: one 4 KiB page */
    li t0, G_L1
    li t1, PTE(G_L0, PTR)
    sd t1, 0(t0)
    li t0, G_L0
    li t1, PTE(DATA1, LEAF_G)
    sd t1, 0(t0)                    /* GPA 0x1_4000_0000 -> DATA1 */
    li t0, VS_ROOT
    li t1, PTE(0xc0000000, LEAF_VS)
    sd t1, 1*8(t0)                  /* GVA 1 GiB -> GPA 3 GiB (no G mapping) */
    li t1, PTE(0x80000000, LEAF_VS)
    sd t1, 2*8(t0)                  /* GVA 2 GiB -> GPA 2 GiB */
    li t1, PTE(0x100000000, LEAF_VS)
    sd t1, 3*8(t0)                  /* GVA 3 GiB -> GPA 4 GiB (G read-only) */
    li t1, PTE(0x140000000, LEAF_VS)
    sd t1, 4*8(t0)                  /* GVA 4 GiB -> GPA 5 GiB */
    li t1, PTE(0x80000000, LEAF_VS_U)
    sd t1, 6*8(t0)                  /* GVA 6 GiB -> GPA 2 GiB, user */
    li t0, DATA0
    li t1, VAL0
    sd t1, 0(t0)
    li t0, DATA1
    li t1, VAL1
    sd t1, 0(t0)
    li t0, (8 << 60) | (G_ROOT >> 12)
    csrw CSR_HGATP, t0
    li t0, (8 << 60) | (VS_ROOT >> 12)
    csrw CSR_VSATP, t0
    hfence.gvma zero, zero
    hfence.vvma zero, zero

    RESET
    ENTER vs, vs_c1                 /* both stages identity */
    CHECK s2, 10, 0xe1
    li t4, VAL0
    CHECKR a0, t4, 0xe2
    li t0, (8 << 60) | (VS_ROOT >> 12)
    CHECKR a1, t0, 0xe3             /* VS satp is vsatp */
    RESET
    ENTER vs, vs_c2                 /* G-stage read-only: load */
    CHECK s2, 10, 0xe4
    CHECKR a0, t4, 0xe5
    RESET
    ENTER vs, vs_c3                 /* G-stage read-only: store */
    CHECK s2, 23, 0xe6
    CHECK s3, 0xc0030008, 0xe7
    CHECK s4, 0x100030008 >> 2, 0xe8
    CHECKBIT s5, 39, 1, 0xe9
    CHECKBIT s5, 38, 1, 0xea        /* GVA: mtval is a guest address */
    la t5, vs_c3_store
    CHECKR s11, t5, 0xeb
    RESET
    ENTER vs, vs_c4                 /* no G-stage mapping */
    CHECK s2, 21, 0xec
    CHECK s3, 0x40000123, 0xed
    CHECK s4, 0xc0000123 >> 2, 0xee
    RESET
    ENTER vs, vs_c5                 /* 3-level G-stage */
    CHECK s2, 21, 0xef
    li t5, VAL1
    CHECKR a0, t5, 0xf0
    CHECK s3, 0x100001008, 0xf1
    CHECK s4, 0x140001008 >> 2, 0xf2
    RESET
    ENTER vs, vs_c6                 /* VS-stage page fault */
    CHECK s2, 13, 0xf3
    CHECK s3, 0x140000010, 0xf4
    CHECK s4, 0, 0xf5
    /* Guest-page and VS-stage faults delegated to HS. */
    li t0, (1 << 21) | (1 << 13)
    csrw medeleg, t0
    RESET
    ENTER vs, vs_c4
    CHECK s2, 9, 0xf6
    CHECK s6, 21, 0xf7
    CHECK s7, 0x40000123, 0xf8
    CHECK s8, 0xc0000123 >> 2, 0xf9
    CHECKBIT s9, 6, 1, 0xfa         /* GVA */
    CHECKBIT s9, 7, 1, 0xfb         /* SPV */
    CHECKBIT s9, 8, 1, 0xfc         /* SPVP */
    RESET
    ENTER vs, vs_c6
    CHECK s2, 9, 0x101
    CHECK s6, 13, 0x102
    CHECK s7, 0x140000010, 0x103
    CHECK s8, 0, 0x104
    CHECKBIT s9, 6, 1, 0x105
    li t0, 1 << 13
    csrw CSR_HEDELEG, t0            /* VS-stage page fault to VS */
    RESET
    ENTER vs, vs_c6
    CHECK s2, 10, 0x106
    CHECK s6, 13, 0x107
    CHECK s7, 0x140000010, 0x108
    la t5, vs_c6_load
    CHECKR s10, t5, 0x109
    csrw medeleg, zero
    csrw CSR_HEDELEG, zero
    /* A G-stage fault on the VS-stage walk of a fetch. */
    li t0, (8 << 60) | (0xc0001000 >> 12)
    csrw CSR_VSATP, t0
    hfence.vvma zero, zero
    RESET
    ENTER vs, vs_c1
    CHECK s2, 20, 0x10a
    la t5, vs_c1
    CHECKR s3, t5, 0x10b
    CHECKR s11, t5, 0x10c
    CHECK s4, (0xc0001000 + 2*8) >> 2, 0x10d
    li t0, (8 << 60) | (VS_ROOT >> 12)
    csrw CSR_VSATP, t0
    hfence.vvma zero, zero
    /* VS changes vsatp to Bare, then back. */
    RESET
    ENTER vs, vs_c7
    CHECK s2, 10, 0x10e
    CHECK a0, VAL0 & 0xff, 0x10f
    csrr t4, CSR_VSATP
    li t5, (8 << 60) | (VS_ROOT >> 12)
    CHECKR t4, t5, 0x110
    csrr t4, satp
    CHECK t4, 0, 0x111              /* HS satp untouched */

    /* HLV/HSV from HS-mode. */
    li t0, H_SPVP
    csrw CSR_HSTATUS, t0
    RESET
    ENTER hs, hs_hlv
    CHECK s2, 9, 0x112
    li t4, VAL0
    CHECKR a0, t4, 0x113
    CHECK a1, 0x55667788, 0x114
    CHECK a2, 0x7788, 0x115
    CHECKBIT s5, 39, 0, 0x116       /* from HS: MPV = 0 */
    RESET
    ENTER hs, hs_hsv_ro
    CHECK s2, 23, 0x117
    CHECK s3, 0xc0030010, 0x118
    CHECK s4, 0x100030010 >> 2, 0x119
    CHECKBIT s5, 39, 0, 0x11a
    csrw CSR_HSTATUS, zero          /* SPVP = 0: accesses as VU */
    RESET
    ENTER hs, hs_hlv_user
    CHECK s2, 9, 0x11b
    CHECKR a0, t4, 0x11c
    RESET
    ENTER hs, hs_hlv_super          /* supervisor page as VU: fault */
    CHECK s2, 13, 0x11d
    CHECK s3, 0x80030000, 0x11e
    li t0, 1 << 13
    csrw medeleg, t0
    RESET
    ENTER hs, hs_hlv_super          /* to HS: GVA = 1, SPV = 0 */
    CHECK s2, 9, 0x11f
    CHECK s6, 13, 0x120
    CHECK s7, 0x80030000, 0x121
    CHECKBIT s9, 6, 1, 0x122
    CHECKBIT s9, 7, 0, 0x123
    csrw medeleg, zero
    /* HLV from U-mode needs hstatus.HU. */
    RESET
    ENTER u, u_hlv
    CHECK s2, 2, 0x124
    li t0, H_HU
    csrw CSR_HSTATUS, t0
    RESET
    ENTER u, u_hlv
    CHECK s2, 8, 0x125
    CHECKR a0, t4, 0x126
    csrw CSR_HSTATUS, zero
    /* HFENCE in HS: fine, but illegal with mstatus.TVM for GVMA. */
    RESET
    ENTER hs, hs_hfence
    CHECK s2, 9, 0x127
    li t0, TVM
    csrs mstatus, t0
    RESET
    ENTER hs, hs_hfence
    CHECK s2, 2, 0x128
    RESET
    ENTER hs, hs_hgatp
    CHECK s2, 2, 0x129
    li t0, TVM
    csrc mstatus, t0

    /* M-mode loads and stores with MPRV = 1 after a trap from VS-mode
     * (MPV = 1, MPP = S): a load, then a store that faults into M. */
    la t0, m_mprv_handler
    csrw mtvec, t0
    li a0, 0
    RESET
    ENTER vs, vs_mprv
    li t4, VAL0
    CHECKR a0, t4, 0x12a
    CHECK s2, 23, 0x12b
    CHECK s3, 0xc0030018, 0x12c
    CHECK s4, 0x100030018 >> 2, 0x12d
    CHECKBIT s5, 39, 0, 0x12e       /* from M: MPV = 0 */

#ifdef SPEC
/* ---------------- S: where QEMU 11.1.3 differs from the spec ---------------- */
    /* mstatus.MPV is writable, and mret enters VS-mode with it. */
    li t0, MPV
    csrs mstatus, t0
    csrr t4, mstatus
    CHECKBIT t4, 39, 1, 0x201
    csrc mstatus, t0
    li t0, 0x1234
    csrw CSR_VSSCRATCH, t0
    RESET
    ENTER vs_mret, vs_b1
    CHECK s2, 10, 0x202
    CHECK a1, 0x1234, 0x203
    /* mstatus.GVA = 0 for a virtual instruction: mtval is the instruction. */
    RESET
    ENTER vs, vs_hstatus
    CHECK s2, 22, 0x204
    CHECKBIT s5, 38, 0, 0x205
    /* GVA = 1 for an HSV fault from HS-mode (V = 0). */
    li t0, H_SPVP
    csrw CSR_HSTATUS, t0
    RESET
    ENTER hs, hs_hsv_ro
    CHECK s2, 23, 0x206
    CHECKBIT s5, 38, 1, 0x207
    CHECKBIT s5, 39, 0, 0x208
    csrw CSR_HSTATUS, zero
    /* GVA = 1 for an M-mode access with MPRV and MPV. */
    la t0, m_mprv_handler
    csrw mtvec, t0
    RESET
    ENTER vs, vs_mprv
    CHECK s2, 23, 0x209
    CHECKBIT s5, 38, 1, 0x20a
    /* A trap into VS-mode leaves hstatus.GVA alone. VU runs through the
     * user gigapage at GVA 6 GiB. */
    li t0, H_GVA
    csrw CSR_HSTATUS, t0
    li t0, 1 << 8
    csrw medeleg, t0
    csrw CSR_HEDELEG, t0
    RESET
    la a0, vu_ecall
    li t0, 0x100000000
    add a0, a0, t0
    call enter_vu
    CHECK s2, 10, 0x20b
    CHECK s6, 8, 0x20c
    csrr t4, CSR_HSTATUS
    CHECKBIT t4, 6, 1, 0x20d
    csrw CSR_HSTATUS, zero
    csrw medeleg, zero
    csrw CSR_HEDELEG, zero
    /* Reserved hstatus bits read as zero. */
    li t4, -1
    csrw CSR_HSTATUS, t4
    csrr t4, CSR_HSTATUS
    li t5, ~(0x3e0 | (0x3f << 12) | (7 << 20) | (1 << 24) | (3 << 32) | (3 << 48))
    and t4, t4, t5
    CHECK t4, 0, 0x20e
    csrw CSR_HSTATUS, zero
    /* vsepc[0] is zero. */
    li t4, 0x1235
    csrw CSR_VSEPC, t4
    csrr t4, CSR_VSEPC
    CHECK t4, 0x1234, 0x20f
    /* hgatp: PPN[1:0] read as zero; an unsupported MODE keeps only MODE. */
    li t4, (8 << 60) | (G_ROOT >> 12) | 3
    csrw CSR_HGATP, t4
    csrr t4, CSR_HGATP
    CHECK t4, (8 << 60) | (G_ROOT >> 12), 0x210
    li t4, (5 << 60) | (0x12 << 44) | (G_ROOT >> 12)
    csrw CSR_HGATP, t4
    csrr t4, CSR_HGATP
    CHECK t4, (8 << 60) | (0x12 << 44) | (G_ROOT >> 12), 0x211
    li t4, (8 << 60) | (G_ROOT >> 12)
    csrw CSR_HGATP, t4
    hfence.gvma zero, zero
    /* sie from VS-mode does not depend on mideleg. */
    csrw mideleg, zero
    li t0, 0x444
    csrw CSR_HIDELEG, t0
    RESET
    ENTER vs, vs_sie
    CHECK a0, 0x222, 0x212
    csrw CSR_VSIE, zero
    csrw CSR_HIDELEG, zero
    /* hvip holds only VS-level bits, also with STIP pending. */
    csrw CSR_STIMECMP, zero
    li t4, -1
    csrw CSR_HVIP, t4
    csrr t4, CSR_HVIP
    CHECK t4, 0x444, 0x213
    csrw CSR_HVIP, zero
    li t0, -1
    csrw CSR_STIMECMP, t0
#endif

    csrw CSR_VSATP, zero            /* both stages Bare again */
    csrw CSR_HGATP, zero
    hfence.gvma zero, zero
    hfence.vvma zero, zero

/* ---------------- D: interrupts ---------------- */
    li t0, 0x444
    csrw CSR_HIDELEG, t0
    li t0, 2
    csrw CSR_VSIE, t0               /* VS SSIE = mie.VSSIE */
    csrr t4, mie
    CHECK t4, 4, 0x131
    li t0, SIE
    csrw CSR_VSSTATUS, t0
    li t0, 4
    csrw CSR_HVIP, t0
    RESET
    ENTER vs, vs_d1                 /* VSSI taken at the first instruction */
    CHECK s2, 10, 0x132
    CHECK s6, INTR | 1, 0x133
    la t5, vs_d1
    CHECKR s10, t5, 0x134
    CHECKBIT s9, 5, 1, 0x135        /* vsstatus.SPIE */
    li t0, SIE
    csrc CSR_VSSTATUS, t0
    RESET
    ENTER vs, vs_d1                 /* vsstatus.SIE = 0: not taken in VS */
    CHECK s2, 10, 0x136
    CHECK s6, -1, 0x137
    RESET
    ENTER vu, vu_ecall              /* but always taken in VU */
    CHECK s2, 10, 0x138
    CHECK s6, INTR | 1, 0x139
    csrw CSR_HVIP, zero
    /* Not delegated by hideleg: an HS interrupt (code 2), taken with V = 1
     * whatever sstatus.SIE is. */
    csrw CSR_HIDELEG, zero
    li t0, 4
    csrw CSR_HIE, t0
    csrw CSR_HVIP, t0
    RESET
    ENTER vs, vs_d1
    CHECK s2, 9, 0x13a
    CHECK s6, INTR | 2, 0x13b
    CHECKBIT s9, 7, 1, 0x13c        /* SPV */
    csrw CSR_HVIP, zero
    csrw CSR_HIE, zero
    /* VS timer from vstimecmp. */
    li t0, 0x444
    csrw CSR_HIDELEG, t0
    li t0, STCE
    csrw CSR_HENVCFG, t0
    li t0, 0x20
    csrw CSR_VSIE, t0               /* VS STIE */
    li t0, SIE
    csrw CSR_VSSTATUS, t0
    csrw CSR_VSTIMECMP, zero
    RESET
    ENTER vs, vs_d1
    CHECK s2, 10, 0x13d
    CHECK s6, INTR | 5, 0x13e
    li t0, -1
    csrw CSR_VSTIMECMP, t0
    csrw CSR_HENVCFG, zero
    csrw CSR_VSIE, zero
    csrw CSR_HIDELEG, zero
    /* sie from VS-mode is vsie: only delegated VS bits. (QEMU also masks
     * the value with mideleg's S bits, so delegate those as SBI firmware
     * does.) */
    li t0, 0x222
    csrw mideleg, t0
    li t0, 0x444
    csrw CSR_HIDELEG, t0
    RESET
    ENTER vs, vs_sie
    CHECK s2, 10, 0x13f
    CHECK a0, 0x222, 0x140
    csrr t4, mie
    CHECK t4, 0x444, 0x141
    csrr t4, CSR_VSIE
    CHECK t4, 0x222, 0x142
    csrw CSR_VSIE, zero
    csrw CSR_HIDELEG, zero
    csrw mideleg, zero

/* ---------------- E: sret between modes ---------------- */
    li t0, 1 << 8
    csrw medeleg, t0
    csrw CSR_HEDELEG, t0
    csrw CSR_VSSTATUS, zero
    RESET
    ENTER hs, hs_sret_vs            /* HS -> VS -> VU -> VS handler */
    CHECK s2, 10, 0x151
    CHECK s6, 8, 0x152
    la t5, vu_ecall
    CHECKR s10, t5, 0x153
    CHECK a0, 0x77, 0x154
    csrr t4, CSR_HSTATUS
    CHECKBIT t4, 7, 0, 0x155        /* sret cleared SPV */
    csrw medeleg, zero
    csrw CSR_HEDELEG, zero
    RESET
    ENTER hs, hs_sret_u             /* HS -> U */
    CHECK s2, 8, 0x156
    CHECKBIT s5, 39, 0, 0x157
    srli t4, s5, 11
    andi t4, t4, 3
    CHECK t4, 0, 0x158

/* ---------------- report ---------------- */
    bnez s0, 2f
    la a0, msg_pass
    call puts
    EXIT 0
1:  j 1b
2:  la a0, msg_fail
    call puts
    EXIT 1
3:  j 3b

/* ---------------- mode entry ---------------- */
/* a0: where to start. VS and VU go through an HS trampoline. */
enter_hs:
    li t1, MPP_S
    mv a1, a0
    j enter
enter_u:
    li t1, 0
    mv a1, a0
    j enter
enter_vs:
    li t1, MPP_S
    la a1, hs_to_vs
    j enter
enter_vu:
    li t1, MPP_S
    la a1, hs_to_vu
    j enter
#ifdef SPEC
enter_vs_mret:                      /* VS through mret with MPV = 1 */
    li t1, MPP_S | MPV
    mv a1, a0
#endif
enter:                              /* t1: MPP (and MPV), a1: mepc */
    li t0, MPP | MPV | MPRV | SIE | SPIE /* HS interrupts off in HS-mode */
    csrc mstatus, t0
    csrs mstatus, t1
    li t0, VAR
    sd ra, 0(t0)
    csrw mepc, a1
    mret

hs_to_vs:                           /* HS-mode: sret into VS at a0 */
    li t0, SPP
    csrs sstatus, t0
    j hs_to_v
hs_to_vu:                           /* HS-mode: sret into VU at a0 */
    li t0, SPP
    csrc sstatus, t0
hs_to_v:
    li t0, H_SPV
    csrs CSR_HSTATUS, t0
    csrw sepc, a0
    sret

/* ---------------- trap handlers ---------------- */
    .balign 4
m_handler:
    csrr s2, mcause
    csrr s3, mtval
    csrr s4, CSR_MTVAL2
    csrr s5, mstatus
    csrr s11, mepc
    li t0, MPRV
    csrc mstatus, t0
#ifndef SPEC
    li t0, H_GVA                    /* see the header */
    csrc CSR_HSTATUS, t0
#endif
    li t0, MPP
    csrs mstatus, t0
    li t0, VAR
    ld t0, 0(t0)
    csrw mepc, t0
    sfence.vma zero, zero
    mret

    .balign 4
m_mprv_handler:                     /* from vs_mprv's ecall: MPV = 1 */
    la t0, m_handler
    csrw mtvec, t0
    li t0, MPRV
    csrs mstatus, t0
    ld a0, 0(t1)                    /* through both stages */
    sd zero, 0(t2)                  /* G-stage read-only: into m_handler */
1:  j 1b

    .balign 4
hs_handler:
    csrr s6, scause
    csrr s7, stval
    csrr s8, CSR_HTVAL
    csrr s9, CSR_HSTATUS
    csrr s10, sepc
    ecall

    .balign 4
vs_handler:
    csrr s6, scause
    csrr s7, stval
    csrr s9, sstatus
    csrr s10, sepc
    ecall

/* ---------------- test bodies ---------------- */
vs_b1:
    csrr a1, sscratch
    csrr a2, sstatus
    li t0, 0x4321
    csrw sscratch, t0
vs_b1_ecall:
    ecall
vs_hstatus:
    csrr a0, CSR_HSTATUS
    ecall
vs_vsstatus:
    csrr a0, CSR_VSSTATUS
    ecall
vs_hfence:
    hfence.vvma zero, zero
    ecall
vs_hlv:
    hlv.d a0, (zero)
    ecall
vs_mhartid:
    csrr a0, mhartid
    ecall
vs_satp:
    csrr a0, satp
    ecall
vs_sfence:
    sfence.vma zero, zero
    ecall
vs_wfi:
    wfi
    ecall
vs_sret:
    sret
    ecall
vs_rdtime:
    rdtime a0
    ecall
vu_sstatus:
    csrr a0, sstatus
    ecall
vu_wfi:
    wfi
    ecall
vu_rdtime:
    rdtime a0
    ecall
vu_ecall:
    ecall

vs_c1:
    li t0, DATA0
    ld a0, 0(t0)
    csrr a1, satp
    ecall
vs_c2:
    li t0, 0xc0030000
    ld a0, 0(t0)
    ecall
vs_c3:
    li t0, 0xc0030008
vs_c3_store:
    sd zero, 0(t0)
    ecall
vs_c4:
    li t0, 0x40000123
    lbu a0, 0(t0)
    ecall
vs_c5:
    li t0, 0x100000000
    ld a0, 0(t0)
    li t0, 0x100001008
    ld a1, 0(t0)
    ecall
vs_c6:
    li t0, 0x140000010
vs_c6_load:
    ld a0, 0(t0)
    ecall
vs_mprv:
    li t1, 0xc0030000
    li t2, 0xc0030018
    ecall
vs_c7:
    csrr t1, satp
    csrw satp, zero
    sfence.vma zero, zero
    li t0, DATA0
    lbu a0, 0(t0)
    csrw satp, t1
    sfence.vma zero, zero
    ecall

hs_hlv:
    li t0, 0xc0030000
    hlv.d a0, (t0)
    li t0, 0x80030000
    hlv.w a1, (t0)
    hlvx.hu a2, (t0)
    ecall
hs_hsv_ro:
    li t0, 0xc0030010
    hsv.d zero, (t0)
    ecall
hs_hlv_user:
    li t0, 0x180030000
    hlv.d a0, (t0)
    ecall
hs_hlv_super:
    li t0, 0x80030000
    hlv.d a0, (t0)
    ecall
u_hlv:
    li t0, 0x180030000
    hlv.d a0, (t0)
    ecall
hs_hfence:
    hfence.vvma zero, zero
    hfence.gvma zero, zero
    ecall
hs_hgatp:
    csrr a0, CSR_HGATP
    ecall

vs_d1:
    nop
    nop
    ecall
vs_sie:
    li t0, 0x222
    csrw sie, t0
    csrr a0, sie
    ecall

hs_sret_vs:
    li t0, H_SPV
    csrs CSR_HSTATUS, t0
    li t0, SPP
    csrs sstatus, t0
    la t0, vs_sret_vu
    csrw sepc, t0
    sret
vs_sret_vu:
    li a0, 0x77
    li t0, SPP
    csrc sstatus, t0
    la t0, vu_ecall
    csrw sepc, t0
    sret
hs_sret_u:
    li t0, SPP
    csrc sstatus, t0
    la t0, vu_ecall
    csrw sepc, t0
    sret

/* ---------------- console ---------------- */
puts:                               /* a0: string; clobbers t2-t5 */
    mv t4, a0
1:  lbu t5, 0(t4)
    beqz t5, 2f
    PUTC t5
    addi t4, t4, 1
    j 1b
2:  ret

puthex:                             /* a0: value; clobbers t2-t6 */
    li t4, 60
1:  srl t5, a0, t4
    andi t5, t5, 15
    li t6, 10
    blt t5, t6, 2f
    addi t5, t5, 'a' - '0' - 10
2:  addi t5, t5, '0'
    PUTC t5
    addi t4, t4, -4
    bgez t4, 1b
    ret

fail:                               /* s1: check id, a0: value */
    mv a7, ra
    mv a6, a0
    addi s0, s0, 1
    la a0, msg_failed
    call puts
    mv a0, s1
    call puthex
    li t5, 32
    PUTC t5
    mv a0, a6
    call puthex
    li t5, 10
    PUTC t5
    mv ra, a7
    ret

msg_start:  .asciz "H-TEST start\n"
msg_failed: .asciz "FAIL "
msg_pass:   .asciz "H-TEST PASS\n"
msg_fail:   .asciz "H-TEST FAIL\n"

#ifdef SAIL
    .section .tohost, "aw", @progbits
    .balign 64
    .globl tohost
tohost:     .dword 0
    .globl fromhost
fromhost:   .dword 0
#endif
