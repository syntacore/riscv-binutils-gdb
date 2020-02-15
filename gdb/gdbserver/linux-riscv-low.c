/* GNU/Linux/RISC-V specific low level interface, GDBserver.

   Copyright (C) 2012-2019 Free Software Foundation, Inc.
   Copyright (C) 2017-2020 Syntacore

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "server.h"
#include "linux-low.h"
#include "nat/gdb_ptrace.h"
#include "elf/common.h"
#include "opcode/riscv.h"
#include "tdesc.h"

#include <linux/ptrace.h>
#include <linux/elf.h>
#include <stdint.h>
#include <inttypes.h>

#include <vector>

#include "../features/riscv/32bit-cpu.c"
#include "../features/riscv/64bit-cpu.c"
#include "../features/riscv/64bit-fpu.c"

#define RISCV_DBG

#ifdef RISCV_DBG
#define DBG_PRINT warning
#else
#define DBG_PRINT(fmt, ...) do {} while (0)
#endif

typedef struct __riscv_d_ext_state riscv_fp_regs_struct;

#define RISCV_X0_REG 0 /* constant zero register */
#define RISCV_SYSNO_REG 17 /* syscall number */
#define RISCV_PC_REG 32
#define RISCV_X_REGS_NUM 33
#define RISCV_F0_REG RISCV_X_REGS_NUM
#define RISCV_F_REGS_NUM 32
#define RISCV_CSR0_REG (RISCV_X_REGS_NUM + RISCV_F_REGS_NUM)
#define RISCV_FCSR_REG (RISCV_CSR0_REG + 3)
#define RISCV_NUM_REGS (RISCV_FCSR_REG + 1)

/* Return true if the size of register 0 is 8 byte.  */

static int
is_64bit_tdesc (void)
{
  struct regcache *regcache = get_thread_regcache (current_thread, 0);

  return register_size (regcache->tdesc, 0) == 8;
}

/* Implementation of linux_target_ops method "cannot_fetch_register".  */

static int
riscv_cannot_fetch_register (int regno)
{
  return regno < 0 || regno >= RISCV_NUM_REGS;
}

/* Implementation of linux_target_ops method "cannot_store_register".  */

static int
riscv_cannot_store_register (int regno)
{
  return regno <= RISCV_X0_REG || regno >= RISCV_NUM_REGS;
}

static int
riscv_inst_size(gdb_byte b0)
{
  return riscv_insn_length(b0);
}

static int
riscv_inst_size_at_pc(CORE_ADDR pc)
{
  gdb_byte buf[4];

  the_target->read_memory(pc, buf, 2);

  return riscv_inst_size(buf[0]);
}

/* Implementation of linux_target_ops method "sw_breakpoint_from_kind".  */

static const gdb_byte ebreak[] = { 0x73, 0x00, 0x10, 0x00, };
static const gdb_byte c_ebreak[] = { 0x02, 0x90 };

static const gdb_byte *
riscv_sw_breakpoint_from_kind(int kind, int *size)
{
  *size = kind;
  switch (kind)
    {
    case 2:
      return c_ebreak;
    case 4:
      return ebreak;
    default:
      internal_error (__FILE__, __LINE__,
		    "riscv_sw_breakpoint_from_kind: unknown kind");
    }
}

int
riscv_breakpoint_kind_from_pc(CORE_ADDR *pcptr)
{
  return riscv_inst_size_at_pc(*pcptr);
}

static int
riscv_breakpoint_at(CORE_ADDR where)
{
  gdb_byte insn[4];

  (*the_target->read_memory) (where, (gdb_byte*) &insn, 4);
  if (insn[0] == ebreak[0] && insn[1] == ebreak[1]
      && insn[2] == ebreak[2] && insn[3] == ebreak[3])
    return 1;
  if (insn[0] == c_ebreak[0] && insn[1] == c_ebreak[1])
    return 1;

  return 0;
}

/* Collect GP registers from REGCACHE to buffer BUF.  */

static void
riscv_fill_gregset(struct regcache *regcache, void *buf)
{
  int i;

  DBG_PRINT("riscv_fill_gregset:");

  if (register_size (regcache->tdesc, 0) == 4)
    {
      for (i = RISCV_X0_REG + 1; i < RISCV_PC_REG; ++i) {
	collect_register (regcache, i, (int32_t*)buf + i);
      }
      collect_register_by_name (regcache, "pc", (int32_t*)buf);

      for (i = 0; i < RISCV_F_REGS_NUM; i += 4) {
	DBG_PRINT("[x%02d] %08" PRIx32 " [x%02d] %08" PRIx32 " [x%02d] %08" PRIx32 " [x%02d] %08" PRIx32,
		  i, ((int32_t*)buf)[i], i + 1, ((int32_t*)buf)[i + 1],
		  i + 2, ((int32_t*)buf)[i + 2], i + 3, ((int32_t*)buf)[i + 3]);
      }
      DBG_PRINT("riscv_fill_gregset: PC %08" PRIx32, *(int32_t*)buf);
    }
  else
    {
      for (i = RISCV_X0_REG + 1; i < RISCV_PC_REG; ++i) {
	collect_register (regcache, i, (int64_t*)buf + i);
      }
      collect_register_by_name (regcache, "pc", (int64_t*)buf);

      for (i = 0; i < RISCV_F_REGS_NUM; i += 4) {
	DBG_PRINT("[x%02d] %016" PRIx64 " [x%02d] %016" PRIx64 " [x%02d] %016" PRIx64 " [x%02d] %016" PRIx64,
		  i, ((int64_t*)buf)[i], i + 1, ((int64_t*)buf)[i + 1],
		  i + 2, ((int64_t*)buf)[i + 2], i + 3, ((int64_t*)buf)[i + 3]);
      }
      DBG_PRINT("riscv_fill_gregset: PC %016" PRIx64, *(int64_t*)buf);
    }
}

/* Supply GP registers contents, stored in BUF, to REGCACHE.  */

static void
riscv_store_gregset(struct regcache *regcache, const void *buf)
{
  int i;

  DBG_PRINT("riscv_store_gregset:");

  if (register_size (regcache->tdesc, 0) == 4)
    {
      for (i = 0; i < RISCV_F_REGS_NUM; i += 4) {
	DBG_PRINT("[x%02d] %08" PRIx32 " [x%02d] %08" PRIx32 " [x%02d] %08" PRIx32 " [x%02d] %08" PRIx32,
		  i, ((int32_t*)buf)[i], i + 1, ((int32_t*)buf)[i + 1],
		  i + 2, ((int32_t*)buf)[i + 2], i + 3, ((int32_t*)buf)[i + 3]);
      }
      DBG_PRINT("riscv_store_gregset: PC %08" PRIx32, *(int32_t*)buf);

      supply_register_zeroed(regcache, RISCV_X0_REG);

      for (i = RISCV_X0_REG + 1; i < RISCV_PC_REG; ++i) {
	supply_register (regcache, i, (int32_t*)buf + i);
      }

      supply_register_by_name (regcache, "pc", (int32_t*)buf);
    }
  else
    {
      for (i = 0; i < RISCV_F_REGS_NUM; i += 4) {
	DBG_PRINT("[x%02d] %016" PRIx64 " [x%02d] %016" PRIx64 " [x%02d] %016" PRIx64 " [x%02d] %016" PRIx64,
		  i, ((int64_t*)buf)[i], i + 1, ((int64_t*)buf)[i + 1],
		  i + 2, ((int64_t*)buf)[i + 2], i + 3, ((int64_t*)buf)[i + 3]);
      }
      DBG_PRINT("riscv_store_gregset: PC %016" PRIx64, *(int64_t*)buf);

      supply_register_zeroed(regcache, RISCV_X0_REG);

      for (i = RISCV_X0_REG + 1; i < RISCV_PC_REG; ++i) {
	supply_register (regcache, i, (int64_t*)buf + i);
      }

      supply_register_by_name (regcache, "pc", (int64_t*)buf);
    }
}

static void
riscv_fill_fpregset(struct regcache *regcache, void *buf)
{
  int i;
  riscv_fp_regs_struct *regset = (riscv_fp_regs_struct*)buf;

  DBG_PRINT("riscv_fill_fpregset:");

  for (i = 0; i < RISCV_F_REGS_NUM; ++i) {
    collect_register (regcache, RISCV_F0_REG + i, &regset->f[i]);
  }
  collect_register_by_name (regcache, "fcsr", &regset->fcsr);

  for (i = 0; i < RISCV_F_REGS_NUM; i += 4) {
    DBG_PRINT("[f%02d] %016" PRIx64 " [f%02d] %016" PRIx64 " [f%02d] %016" PRIx64 " [f%02d] %016" PRIx64,
	      i, (uint64_t)regset->f[i], i + 1, (uint64_t)regset->f[i + 1],
	      i + 2, (uint64_t)regset->f[i + 2], i + 3, (uint64_t)regset->f[i + 3]);
  }
  DBG_PRINT("riscv_fill_fpregset: FCSR %08" PRIx32, (int32_t)regset->fcsr);
}

static void
riscv_store_fpregset(struct regcache *regcache, const void *buf)
{
  int i;
  const riscv_fp_regs_struct *regset = (const riscv_fp_regs_struct*)buf;

  DBG_PRINT("riscv_store_fpregset:");

  for (i = 0; i < RISCV_F_REGS_NUM; i += 4) {
    DBG_PRINT("[f%02d] %016" PRIx64 " [f%02d] %016" PRIx64 " [f%02d] %016" PRIx64 " [f%02d] %016" PRIx64,
	      i, (uint64_t)regset->f[i], i + 1, (uint64_t)regset->f[i + 1],
	      i + 2, (uint64_t)regset->f[i + 2], i + 3, (uint64_t)regset->f[i + 3]);
  }
  DBG_PRINT("riscv_store_fpregset: FCSR %08" PRIx32, (int32_t)regset->fcsr);

  for (i = 0; i < RISCV_F_REGS_NUM; ++i)
    supply_register (regcache, RISCV_F0_REG + i, &regset->f[i]);
  supply_register_by_name (regcache, "fcsr", &regset->fcsr);
}

/* Implementation of linux_target_ops method "get_pc".  */

static CORE_ADDR
riscv_get_pc (struct regcache *regcache)
{
  if (register_size (regcache->tdesc, 0) == 8)
    return linux_get_pc_64bit (regcache);
  else
    return linux_get_pc_32bit (regcache);
}

/* Implementation of linux_target_ops method "set_pc".  */

static void
riscv_set_pc (struct regcache *regcache, CORE_ADDR pc)
{
  if (register_size (regcache->tdesc, 0) == 8)
    linux_set_pc_64bit (regcache, pc);
  else
    linux_set_pc_32bit (regcache, pc);
}

static struct regset_info rv64_regsets[] =
{
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS,
    32 * 8 + 8, GENERAL_REGS,
    riscv_fill_gregset, riscv_store_gregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRFPREG,
    sizeof(riscv_fp_regs_struct), FP_REGS,
    riscv_fill_fpregset, riscv_store_fpregset
  },
  NULL_REGSET
};

static struct regsets_info rv64_regsets_info =
  {
    rv64_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct regs_info rv64_regs_info =
  {
    NULL, /* regset_bitmap */
    NULL, /* usrregs */
    &rv64_regsets_info,
  };

static struct regset_info rv32_regsets[] =
{
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS,
    32 * 4 + 4, GENERAL_REGS,
    riscv_fill_gregset, riscv_store_gregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRFPREG,
    sizeof(riscv_fp_regs_struct), FP_REGS,
    riscv_fill_fpregset, riscv_store_fpregset
  },
  NULL_REGSET
};

static struct regsets_info rv32_regsets_info =
  {
    rv32_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct regs_info rv32_regs_info =
  {
    NULL, /* regset_bitmap */
    NULL, /* usrregs */
    &rv32_regsets_info,
  };

static const struct regs_info *
riscv_regs_info (void)
{
  if (!is_64bit_tdesc ())
    return &rv32_regs_info;

  return &rv64_regs_info;
}

/* Implementation of linux_target_ops method "supports_tracepoints".  */
#if 0
/* TODO: tracepoints support */
static int
riscv_supports_tracepoints (void)
{
  return 0;
}
#endif

static void
riscv_arch_setup (void)
{
  unsigned int machine;
  int is_elf64;
  int tid;

  static const char *expedite_riscv_regs[] = { "sp", "pc", NULL };

  /* All possible RISC-V Linux target descriptors  */
  /* TODO: RV128 support */
  static struct target_desc *tdesc_rv32_linux = NULL;
#if __riscv_xlen > 32
  static struct target_desc *tdesc_rv64_linux = NULL;
#endif

  tid = lwpid_of (current_thread);

  is_elf64 = linux_pid_exe_is_elf_64_file (tid, &machine);

  if (is_elf64)
    {
#if __riscv_xlen == 32
      error (_("Can't debug 64-bit process with 32-bit GDBserver"));
#else
      if (!tdesc_rv64_linux)
        {
          tdesc_rv64_linux = allocate_target_description ();
#ifndef IN_PROCESS_AGENT
          set_tdesc_architecture (tdesc_rv64_linux, "riscv:rv64");
          set_tdesc_osabi (tdesc_rv64_linux, "GNU/Linux");
#endif
          long regnum = 0;
          regnum = create_feature_riscv_64bit_cpu (tdesc_rv64_linux, regnum);
          regnum = create_feature_riscv_64bit_fpu (tdesc_rv64_linux, regnum);
          init_target_desc (tdesc_rv64_linux, expedite_riscv_regs);
        }
      current_process ()->tdesc = tdesc_rv64_linux;
#endif
    }
  else
    {
      if (!tdesc_rv32_linux)
        {
          tdesc_rv32_linux = allocate_target_description ();
#ifndef IN_PROCESS_AGENT
          set_tdesc_architecture (tdesc_rv32_linux, "riscv:rv32");
          set_tdesc_osabi (tdesc_rv32_linux, "GNU/Linux");
#endif
          long regnum = 0;
          regnum = create_feature_riscv_32bit_cpu (tdesc_rv32_linux, regnum);
          regnum = create_feature_riscv_64bit_fpu (tdesc_rv32_linux, regnum);
          init_target_desc (tdesc_rv32_linux, expedite_riscv_regs);
        }
      current_process ()->tdesc = tdesc_rv32_linux;
    }
}

/* Fetch the next possible PCs after the current instruction executes.  */

static std::vector<CORE_ADDR>
riscv_get_next_pcs(struct regcache *regcache)
{
  // unsigned long pc_val;
  CORE_ADDR nextpc;
  gdb_byte buf[4];
  std::vector<CORE_ADDR> next_pcs;
  CORE_ADDR pc = regcache_read_pc(regcache);
  int inst_op;

  the_target->read_memory(pc, buf, 2);
  inst_op = (buf[0] & 0x3);

  DBG_PRINT("RISCV_get_next_pcs(): pc %08lx code %04x", (unsigned long)pc, (unsigned)buf[0] + ((unsigned)buf[1] << 8));

  if (inst_op == 1) { // RVC encoding #1
    int inst_func = buf[1] & 0xe0;
    if (inst_func == 0xa0 || inst_func == 0x20) { // J[AL]
      const int16_t imm = (buf[1] << 8) | buf[0];
      int16_t offs =
	(((int16_t)(imm << (15 - 12)) >> (15 - 11)) & ~((1 << 11) - 1)) |
	((imm >> (11 - 4)) & (1 << 4)) |
	((imm >> (10 - 9)) & (3 << 8)) |
	((imm << (10 - 8)) & (1 << 10)) |
	((imm >> (7 - 6)) & (1 << 6)) |
	((imm << (7 - 6)) & (1 << 7)) |
	((imm >> (5 - 3)) & (7 << 1)) |
	((imm << (5 - 2)) & (1 << 5))
	;
      nextpc = (CORE_ADDR)((unsigned long)pc + (long)offs);
      DBG_PRINT("RISCV_get_next_pcs(C.%s): pc %08lx code %04x offs %ld newpc %08lx",
		inst_func == 0xa0 ? "J" : "JAL",
		(unsigned long)pc, (unsigned)imm, (long)offs, (unsigned long)nextpc);
    } else if (inst_func == 0xc0 || inst_func == 0xe0) { // BEQZ || BNEZ
      const int16_t imm = (buf[1] << 8) | buf[0];
      int16_t offs =
	(((int16_t)(imm << (15 - 12)) >> (15 - 8)) & ~((1 << 8) - 1)) |
	((imm >> (11 - 4)) & (3 << 3)) |
	((imm << (7 - 6)) & (3 << 6)) |
	((imm >> (4 - 2)) & (3 << 1)) |
	((imm << (5 - 2)) & (1 << 5))
	;
      // add branch FALSE
      next_pcs.push_back((CORE_ADDR)((unsigned long)pc + 2));
      // add branch TRUE
      nextpc = (CORE_ADDR)((unsigned long)pc + (long)offs);
      DBG_PRINT("RISCV_get_next_pcs(C.%s): pc %08lx code %04x offs %ld newpc %08lx",
		inst_func == 0xc0 ? "BEQZ" : "BNEZ",
		(unsigned long)pc, (unsigned)imm, (long)offs, (unsigned long)nextpc);
    } else { // all others
      nextpc = (CORE_ADDR)((unsigned long)pc + 2);
    }
  } else if (inst_op == 2) { // RVC encoding #2
    int inst_func = buf[1] & 0xe0;
    int base_regn = ((buf[1] << 1) | ((buf[0] >> 7) & 0x1)) & 0x1f;
    if (inst_func == 0x80 && (buf[0] & 0x7f) == 0x2 && base_regn != 0) { // C.J[AL]R
      const int16_t imm = (buf[1] << 8) | buf[0];
      long base = 0;
      collect_register(regcache, base_regn, &base);
      nextpc = (CORE_ADDR)(base & ~0x1);
      DBG_PRINT("RISCV_get_next_pcs(C.J[AL]R): pc %08lx code %04x reg %d newpc %08lx", (unsigned long)pc, (unsigned)imm, base_regn, (unsigned long)nextpc);
    } else { // all others
      nextpc = (CORE_ADDR)((unsigned long)pc + 2);
    }
  } else if (inst_op == 3) { // RVI encoding
    the_target->read_memory(pc, buf, 4);

    int inst_op2 = buf[0] & 0x7c;

    if (inst_op2 == 0x60) { // BRANCH
      const int32_t imm = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
      int32_t offs =
	((imm >> (31 - 12)) & ~((1 << 12) - 1)) |
	((imm >> (30 - 10)) & (((1 << 6) - 1) << 5)) |
	((imm << (11 - 7)) & (1 << 11)) |
	((imm >> (11 - 4)) & (((1 << 4) - 1) << 1))
	;
      // FIXME: calculate branch result and push only one address
      // add branch FALSE
      next_pcs.push_back((CORE_ADDR)((unsigned long)pc + 4));
      // add branch TRUE
      nextpc = (CORE_ADDR)((unsigned long)pc + (long)offs);
      DBG_PRINT("RISCV_get_next_pcs(BRANCH): pc %08lx code %08x offs %ld newpc %08lx", (unsigned long)pc, (unsigned)imm, (long)offs, (unsigned long)nextpc);
    } else if (inst_op2 == 0x64) { // JALR
      const int32_t imm = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
      int32_t offs = (int32_t)((buf[3] << 24) | (buf[2] << 16)) >> (31 - 11);
      int base_regn = ((buf[2] << 1) | ((buf[1] >> 7) & 0x1)) & 0x1f;
      long base = 0;
      collect_register (regcache, base_regn, &base);
      nextpc = (CORE_ADDR)((base + offs) & ~0x1);
      DBG_PRINT("RISCV_get_next_pcs(JALR): pc %08lx code %08x reg %d base %08lx offs %ld newpc %08lx", (unsigned long)pc, (unsigned)imm, base_regn, base, (long)offs, (unsigned long)nextpc);
    } else if (inst_op2 == 0x6c) { // JAL
      const int32_t imm = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
      int32_t offs =
	((imm >> (31 - 20)) & ~((1 << 20) - 1)) |
	((imm >> (30 - 10)) & (0x3ff << 1)) |
	((imm >> (20 - 11)) & (1 << 11)) |
	((imm >> (19 - 19)) & (0xff << 12))
	;
      nextpc = (CORE_ADDR)((unsigned long)pc + (long)offs);
      DBG_PRINT("RISCV_get_next_pcs(JAL): pc %08lx code %08x offs %ld newpc %08lx", (unsigned long)pc, (unsigned)imm, (long)offs, (unsigned long)nextpc);
    } else { // all others
      nextpc = (CORE_ADDR)((unsigned long)pc + 4);
    }
  } else {
    nextpc = (CORE_ADDR)((unsigned long)pc + riscv_inst_size(buf[0]));
  }

  next_pcs.push_back(nextpc);

  return next_pcs;
}

/* Implementation of linux_target_ops method "supports_z_point_type".  */

static int
riscv_supports_z_point_type (char z_type)
{
  switch (z_type)
    {
    case Z_PACKET_SW_BP:
      return 1;
    default:
      return 0;
    }
}

/* Implementation of linux_target_ops method "get_syscall_trapinfo".  */

static void
riscv_get_syscall_trapinfo (struct regcache *regcache, int *sysno)
{
  long sn = -1;

  // collect_register_by_name (regcache, "x17", &sn);
  collect_register (regcache, RISCV_SYSNO_REG, &sn);

  *sysno = sn;
}

struct linux_target_ops the_low_target =
{
  riscv_arch_setup,
  riscv_regs_info,
  riscv_cannot_fetch_register,
  riscv_cannot_store_register,
  NULL, /* fetch_register */
  riscv_get_pc,
  riscv_set_pc,
  riscv_breakpoint_kind_from_pc, /* breakpoint_kind_from_pc */
  riscv_sw_breakpoint_from_kind,
  riscv_get_next_pcs, /* get_next_pcs */
  0, /* decr_pc_after_break */
  riscv_breakpoint_at,
  riscv_supports_z_point_type, /* supports_z_point_type */
  NULL, /* insert_point */
  NULL, /* remove_point */
  NULL, /* stopped_by_watchpoint */
  NULL, /* stopped_data_address */
  NULL, /* collect_ptrace_register */
  NULL, /* supply_ptrace_register */
  NULL, /* siginfo_fixup */
  NULL, /* new_process */
  NULL, /* delete_process */
  NULL, /* new_thread */
  NULL, /* delete_thread */
  NULL, /* new_fork */
  NULL, /* prepare_to_resume */
  NULL, /* process_qsupported */
  NULL, /* riscv_supports_tracepoints */
  NULL, /* get_thread_area */
  NULL, /* install_fast_tracepoint_jump_pad */
  NULL, /* emit_ops */
  NULL, /* get_min_fast_tracepoint_insn_len */
  NULL, /* supports_range_stepping */
  NULL, /* breakpoint_kind_from_current_state */
  NULL, /* supports_hardware_single_step */
  riscv_get_syscall_trapinfo,
};

void
initialize_low_arch (void)
{
  initialize_regsets_info (&rv32_regsets_info);
  initialize_regsets_info (&rv64_regsets_info);
}
