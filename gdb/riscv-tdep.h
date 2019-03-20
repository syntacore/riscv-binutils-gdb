/* Target-dependent header for the RISC-V architecture, for GDB, the
   GNU Debugger.

   Copyright (C) 2018-2019 Free Software Foundation, Inc.

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

#ifndef RISCV_TDEP_H
#define RISCV_TDEP_H

#include "arch/riscv.h"

/* RiscV register numbers.  */
enum
{
  RISCV_ZERO_REGNUM = 0,	/* Read-only register, always 0.  */
  RISCV_RA_REGNUM = 1,		/* Return Address.  */
  RISCV_SP_REGNUM = 2,		/* Stack Pointer.  */
  RISCV_GP_REGNUM = 3,		/* Global Pointer.  */
  RISCV_TP_REGNUM = 4,		/* Thread Pointer.  */
  RISCV_FP_REGNUM = 8,		/* Frame Pointer.  */
  RISCV_A0_REGNUM = 10,		/* First argument.  */
  RISCV_A1_REGNUM = 11,		/* Second argument.  */
  RISCV_PC_REGNUM = 32,		/* Program Counter.  */

  RISCV_RV32E_LAST_REGNUM = 15,
  RISCV_NUM_INTEGER_REGS = 32,

  RISCV_FIRST_GP_REGNUM = RISCV_ZERO_REGNUM,		/* First GP Register */
  RISCV_LAST_GP_REGNUM = RISCV_FIRST_GP_REGNUM + 31,	/* Last GP Register */
  RISCV_FIRST_FP_REGNUM = RISCV_NUM_INTEGER_REGS + 1,	/* First FPU Register */
  RISCV_LAST_FP_REGNUM = RISCV_FIRST_FP_REGNUM + 31,	/* Last FPU Register */
  RISCV_FIRST_CSR_REGNUM = RISCV_LAST_FP_REGNUM + 1,	/* First CSR Register */
  RISCV_FA0_REGNUM = RISCV_FIRST_FP_REGNUM + 10,
  RISCV_FA1_REGNUM = RISCV_FA0_REGNUM + 1,

#define DECLARE_CSR(name, num) \
  RISCV_ ## num ## _REGNUM = RISCV_FIRST_CSR_REGNUM + num,
#include "opcode/riscv-opc.h"
#undef DECLARE_CSR
  RISCV_LAST_CSR_REGNUM = RISCV_FIRST_CSR_REGNUM + 4095,

  RISCV_NUM_REGS,
  RISCV_VIRT_PRIV_REGNUM = RISCV_NUM_REGS,
  RISCV_VIRT_NUM_REGS,
};

/* RiscV DWARF register numbers.  */
enum
{
  RISCV_DWARF_REGNUM_X0 = 0,
  RISCV_DWARF_REGNUM_X31 = 31,
  RISCV_DWARF_REGNUM_F0 = 32,
  RISCV_DWARF_REGNUM_F31 = 63,
};

#define RISCV_PC_REGNAME "pc"
#define RISCV_VIRT_PRIV_REGNAME "priv"

#define RISCV_GDB_FEATURE_PREFIX "org.gnu.gdb.riscv."
#define RISCV_GDB_FEATURE_CORE RISCV_GDB_FEATURE_PREFIX "core"
#define RISCV_GDB_FEATURE_FPU  RISCV_GDB_FEATURE_PREFIX "fpu"
#define RISCV_GDB_FEATURE_CPU  RISCV_GDB_FEATURE_PREFIX "cpu"
#define RISCV_GDB_FEATURE_CSR  RISCV_GDB_FEATURE_PREFIX "csr"
#define RISCV_GDB_FEATURE_VIRT RISCV_GDB_FEATURE_PREFIX "virtual"

/* RISC-V specific per-architecture information.  */
struct gdbarch_tdep
{
  /* Features about the target hardware that impact how the gdbarch is
     configured.  Two gdbarch instances are compatible only if this field
     matches.  */
  struct riscv_gdbarch_features isa_features;

  /* Features about the abi that impact how the gdbarch is configured.  Two
     gdbarch instances are compatible only if this field matches.  */
  struct riscv_gdbarch_features abi_features;

  /* ISA-specific data types.  */
  struct type *riscv_fpreg_d_type = nullptr;
  struct type *riscv_fpreg_f_type = nullptr;
  struct type *riscv_priv_type = nullptr;
};


/* Return the width in bytes  of the general purpose registers for GDBARCH.
   Possible return values are 4, 8, or 16 for RiscV variants RV32, RV64, or
   RV128.  */
extern int riscv_isa_xlen (struct gdbarch *gdbarch);

/* Return the width in bytes of the hardware floating point registers for
   GDBARCH.  If this architecture has no floating point registers, then
   return 0.  Possible values are 4, 8, or 16 for depending on which of
   single, double or quad floating point support is available.  */
extern int riscv_isa_flen (struct gdbarch *gdbarch);

/* Return the width in bytes of the general purpose register abi for
   GDBARCH.  This can be equal to, or less than RISCV_ISA_XLEN and reflects
   how the binary was compiled rather than the hardware that is available.
   It is possible that a binary compiled for RV32 is being run on an RV64
   target, in which case the isa xlen is 8-bytes, and the abi xlen is
   4-bytes.  This will impact how inferior functions are called.  */
extern int riscv_abi_xlen (struct gdbarch *gdbarch);

/* Return the width in bytes of the floating point register abi for
   GDBARCH.  This reflects how the binary was compiled rather than the
   hardware that is available.  It is possible that a binary is compiled
   for single precision floating point, and then run on a target with
   double precision floating point.  A return value of 0 indicates that no
   floating point abi is in use (floating point arguments will be passed
   in integer registers) other possible return value are 4, 8, or 16 as
   with RISCV_ISA_FLEN.  */
extern int riscv_abi_flen (struct gdbarch *gdbarch);

#endif /* RISCV_TDEP_H */
