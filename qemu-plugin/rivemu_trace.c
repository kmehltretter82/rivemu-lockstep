/*
 * rivemu_trace: QEMU TCG plugin that streams a compact execution trace of
 * vCPU 0 for `rivemu-lockstep boot-trace`.
 *
 * Usage: -plugin librivemu_trace.so,out=<path>[,init=<csr>:<hex>]...
 *   out   where to write the trace (usually a FIFO)
 *   init  register values to set when vCPU 0 first reaches the firmware
 *         entry 0x80000000, where the trace starts with an 'S' record
 *         (implementation-defined reset values that rivemu chose
 *         differently, such as menvcfg)
 *
 * Little-endian records, each starting with a one-byte tag:
 *   'I' pc:u64 rd:u8 value:u64   before executing the instruction at pc;
 *                                rd/value is the destination register of the
 *                                previously executed instruction and its
 *                                current value (rd 0 when there is none).
 *   'D' kind:u8 from:u64 to:u64  a trap (kind 1 interrupt, 2 exception,
 *                                4 host call) from pc `from` to `to`.
 *   'C' priv mstatus mcause mepc mtval scause sepc stval satp : u64 each,
 *                                sent before the first 'I' after a trap.
 *   'S' x1..x31 priv mstatus satp : u64 each, the state before the
 *                                instruction of the preceding 'I' record;
 *                                every 2^16 instructions and at the entry.
 *
 * Only vCPU 0 is traced; run QEMU with -smp 1.
 */
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define SNAPSHOT_INTERVAL (1u << 16)

static int out_fd = -1;
static uint8_t out_buf[1 << 20];
static size_t out_len;

static struct qemu_plugin_register *gpr[32];
static const char *gpr_names[32] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "fp", "s1", "a0",
    "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5",
    "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
};
enum { PRIV, MSTATUS, MCAUSE, MEPC, MTVAL, SCAUSE, SEPC, STVAL, SATP, NCSR };
static const char *csr_names[NCSR] = {
    "priv", "mstatus", "mcause", "mepc", "mtval", "scause", "sepc", "stval", "satp",
};
static struct qemu_plugin_register *csr[NCSR];

#define ENTRY_PC 0x80000000ull
#define MAX_INIT 8
static char *init_name[MAX_INIT];
static uint64_t init_value[MAX_INIT];
static struct qemu_plugin_register *init_reg[MAX_INIT];
static int n_init;
static int started;

static GByteArray *reg_buf;
static uint8_t prev_rd;
static int need_csrs;
static uint64_t executed;

static void flush_out(void)
{
    size_t off = 0;
    while (off < out_len) {
        ssize_t n = write(out_fd, out_buf + off, out_len - off);
        if (n <= 0) {
            /* The reader went away: stop QEMU. */
            _exit(0);
        }
        off += (size_t)n;
    }
    out_len = 0;
}

static void emit(const void *data, size_t len)
{
    if (out_len + len > sizeof(out_buf)) {
        flush_out();
    }
    memcpy(out_buf + out_len, data, len);
    out_len += len;
}

static void emit_u8(uint8_t v) { emit(&v, 1); }
static void emit_u64(uint64_t v) { emit(&v, 8); }

static uint64_t read_reg(struct qemu_plugin_register *reg)
{
    uint64_t v = 0;
    if (!reg) {
        return 0;
    }
    g_byte_array_set_size(reg_buf, 0);
    if (qemu_plugin_read_register(reg, reg_buf)) {
        memcpy(&v, reg_buf->data, reg_buf->len < 8 ? reg_buf->len : 8);
    }
    return v;
}

/* Destination register of an instruction, or a register it reads when it
 * has none: comparing that one is harmless, both sides must agree. */
static uint8_t insn_rd(uint32_t w, size_t len)
{
    if (len == 4) {
        return (w >> 7) & 31;
    }
    uint32_t f3 = (w >> 13) & 7;
    switch (w & 3) {
    case 0: /* c.addi4spn, c.lw/ld/fld, stores: rd'/rs2' in bits 4:2 */
        return 8 + ((w >> 2) & 7);
    case 1:
        if (f3 == 4) { /* c.srli/srai/andi/sub/xor/or/and/subw/addw */
            return 8 + ((w >> 7) & 7);
        }
        if (f3 >= 5) { /* c.j, c.beqz, c.bnez */
            return 0;
        }
        return (w >> 7) & 31; /* c.addi, c.addiw, c.li, c.lui/addi16sp */
    default:
        if (f3 == 4 && ((w >> 12) & 1) && ((w >> 2) & 31) == 0 && ((w >> 7) & 31)) {
            return 1; /* c.jalr */
        }
        return (w >> 7) & 31;
    }
}

struct insn_info {
    uint64_t pc;
    uint8_t rd;
};

static void emit_csrs(void)
{
    emit_u8('C');
    for (int i = 0; i < NCSR; i++) {
        emit_u64(read_reg(csr[i]));
    }
}

static void emit_snapshot(void)
{
    emit_u8('S');
    for (int i = 1; i < 32; i++) {
        emit_u64(read_reg(gpr[i]));
    }
    emit_u64(read_reg(csr[PRIV]));
    emit_u64(read_reg(csr[MSTATUS]));
    emit_u64(read_reg(csr[SATP]));
}

static void insn_exec(unsigned int vcpu_index, void *udata)
{
    const struct insn_info *info = udata;
    if (vcpu_index != 0) {
        return;
    }
    if (need_csrs) {
        need_csrs = 0;
        emit_csrs();
    }
    if (!started) {
        return;
    }
    emit_u8('I');
    emit_u64(info->pc);
    emit_u8(prev_rd);
    emit_u64(prev_rd ? read_reg(gpr[prev_rd]) : 0);
    prev_rd = info->rd;
    /* After the 'I' record, so that the reader has applied the previous
     * instruction's result (which it may take from QEMU) first. */
    if (++executed % SNAPSHOT_INTERVAL == 0) {
        emit_snapshot();
    }
}

/* The firmware entry: apply init= values once, then start the trace. */
static void entry_exec(unsigned int vcpu_index, void *udata)
{
    if (vcpu_index == 0 && !started) {
        for (int i = 0; i < n_init; i++) {
            g_byte_array_set_size(reg_buf, 0);
            g_byte_array_append(reg_buf, (const guint8 *)&init_value[i], 8);
            if (!qemu_plugin_write_register(init_reg[i], reg_buf)) {
                fprintf(stderr, "rivemu_trace: cannot write %s\n", init_name[i]);
                exit(1);
            }
        }
        started = 1;
        prev_rd = 0;
        emit_snapshot();
    }
    insn_exec(vcpu_index, udata);
}

static void vcpu_discon(unsigned int vcpu_index, enum qemu_plugin_discon_type type,
                        uint64_t from_pc, uint64_t to_pc, void *userdata)
{
    if (vcpu_index != 0 || !started) {
        return;
    }
    emit_u8('D');
    emit_u8((uint8_t)type);
    emit_u64(from_pc);
    emit_u64(to_pc);
    need_csrs = 1;
}

static void vcpu_tb_trans(struct qemu_plugin_tb *tb, void *userdata)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint32_t w = 0;
        size_t len = qemu_plugin_insn_size(insn);
        qemu_plugin_insn_data(insn, &w, len > 4 ? 4 : len);
        struct insn_info *info = g_new(struct insn_info, 1);
        info->pc = qemu_plugin_insn_vaddr(insn);
        info->rd = insn_rd(w, len);
        if (info->pc == ENTRY_PC) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, entry_exec, QEMU_PLUGIN_CB_RW_REGS, info);
        } else {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec, QEMU_PLUGIN_CB_R_REGS, info);
        }
    }
}

static void vcpu_init(unsigned int vcpu_index, void *userdata)
{
    if (vcpu_index != 0) {
        return;
    }
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *d = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        for (int r = 0; r < 32; r++) {
            if (!strcmp(d->name, gpr_names[r])) {
                gpr[r] = d->handle;
            }
        }
        for (int c = 0; c < NCSR; c++) {
            if (!strcmp(d->name, csr_names[c])) {
                csr[c] = d->handle;
            }
        }
        for (int k = 0; k < n_init; k++) {
            if (!strcmp(d->name, init_name[k])) {
                init_reg[k] = d->handle;
            }
        }
    }
    for (int k = 0; k < n_init; k++) {
        if (!init_reg[k]) {
            fprintf(stderr, "rivemu_trace: register %s not found\n", init_name[k]);
            exit(1);
        }
    }
    for (int r = 1; r < 32; r++) {
        if (!gpr[r]) {
            fprintf(stderr, "rivemu_trace: register %s not found\n", gpr_names[r]);
            exit(1);
        }
    }
    for (int c = 0; c < NCSR; c++) {
        if (!csr[c]) {
            fprintf(stderr, "rivemu_trace: register %s not found\n", csr_names[c]);
            exit(1);
        }
    }
}

static void plugin_exit(void *userdata)
{
    flush_out();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *out = NULL;
    for (int i = 0; i < argc; i++) {
        if (g_str_has_prefix(argv[i], "out=")) {
            out = argv[i] + 4;
        } else if (g_str_has_prefix(argv[i], "init=") && n_init < MAX_INIT) {
            char **kv = g_strsplit(argv[i] + 5, ":", 2);
            if (!kv[0] || !kv[1]) {
                fprintf(stderr, "rivemu_trace: bad %s (want init=<csr>:<hex>)\n", argv[i]);
                return -1;
            }
            init_name[n_init] = g_strdup(kv[0]);
            init_value[n_init] = g_ascii_strtoull(kv[1], NULL, 16);
            n_init++;
            g_strfreev(kv);
        } else {
            fprintf(stderr, "rivemu_trace: unknown option %s\n", argv[i]);
            return -1;
        }
    }
    if (!out) {
        fprintf(stderr, "rivemu_trace: out=<path> is required\n");
        return -1;
    }
    out_fd = open(out, O_WRONLY);
    if (out_fd < 0) {
        perror(out);
        return -1;
    }
    reg_buf = g_byte_array_new();
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans, NULL);
    qemu_plugin_register_vcpu_discon_cb(id, QEMU_PLUGIN_DISCON_ALL, vcpu_discon, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
