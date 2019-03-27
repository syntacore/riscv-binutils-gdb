/* Target-dependent code for the RISC-V architecture, for GDB.

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
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "defs.h"
#include "frame.h"
#include "inferior.h"
#include "symtab.h"
#include "value.h"
#include "gdbcmd.h"
#include "language.h"
#include "gdbcore.h"
#include "symfile.h"
#include "objfiles.h"
#include "gdbtypes.h"
#include "target.h"
#include "arch-utils.h"
#include "regcache.h"
#include "osabi.h"
#include "riscv-tdep.h"
#include "block.h"
#include "reggroups.h"
#include "opcode/riscv.h"
#include "elf/riscv.h"
#include "elf-bfd.h"
#include "symcat.h"
#include "dis-asm.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "infcall.h"
#include "floatformat.h"
#include "remote.h"
#include "target-descriptions.h"
#include "dwarf2-frame.h"
#include "user-regs.h"
#include "valprint.h"
#include "common-defs.h"
#include "opcode/riscv-opc.h"
#include "cli/cli-decode.h"
#include "observable.h"
#include "prologue-value.h"
#include "arch/riscv.h"

// #define RISCV_DBG

#ifdef RISCV_DBG
#define DBG_PRINT warning
#define RISCV_DBG_DFLT 1
#else
#define DBG_PRINT(fmt, ...) do {} while (0)
#define RISCV_DBG_DFLT 0
#endif

#define RISCV_SCR_CUSTOM_CSR 1


/* The stack must be 16-byte aligned.  */
#define SP_ALIGNMENT 16

/* The biggest alignment that the target supports.  */
#define BIGGEST_ALIGNMENT 16

/* Define a series of is_XXX_insn functions to check if the value INSN
   is an instance of instruction XXX.  */
#define DECLARE_INSN(INSN_NAME, INSN_MATCH, INSN_MASK) \
static inline bool is_ ## INSN_NAME ## _insn (long insn) \
{ \
  return (insn & INSN_MASK) == INSN_MATCH; \
}
#include "opcode/riscv-opc.h"
#undef DECLARE_INSN

/* Cached information about a frame.  */

struct riscv_unwind_cache
{
  /* The register from which we can calculate the frame base.  This is
     usually $sp or $fp.  */
  int frame_base_reg;

  /* The offset from the current value in register FRAME_BASE_REG to the
     actual frame base address.  */
  int frame_base_offset;

  /* Information about previous register values.  */
  struct trad_frame_saved_reg *regs;

  /* The id for this frame.  */
  struct frame_id this_id;

  /* The base (stack) address for this frame.  This is the stack pointer
     value on entry to this frame before any adjustments are made.  */
  CORE_ADDR frame_base;
};

struct register_alias
{
  const char *name;
  int regnum;
};

static const struct register_alias riscv_xreg_aliases[] =
  {
    { "zero", 0 },
    { "ra", 1 },
    { "sp", 2 },
    { "gp", 3 },
    { "tp", 4 },
    { "t0", 5 },
    { "t1", 6 },
    { "t2", 7 },
    { "fp", 8 },
    { "s0", 8 },
    { "s1", 9 },
    { "a0", 10 },
    { "a1", 11 },
    { "a2", 12 },
    { "a3", 13 },
    { "a4", 14 },
    { "a5", 15 },
    { "a6", 16 },
    { "a7", 17 },
    { "s2", 18 },
    { "s3", 19 },
    { "s4", 20 },
    { "s5", 21 },
    { "s6", 22 },
    { "s7", 23 },
    { "s8", 24 },
    { "s9", 25 },
    { "s10", 26 },
    { "s11", 27 },
    { "t3", 28 },
    { "t4", 29 },
    { "t5", 30 },
    { "t6", 31 },
  };

static const struct register_alias riscv_freg_aliases[] =
  {
    { "ft0", 33 },
    { "ft1", 34 },
    { "ft2", 35 },
    { "ft3", 36 },
    { "ft4", 37 },
    { "ft5", 38 },
    { "ft6", 39 },
    { "ft7", 40 },
    { "fs0", 41 },
    { "fs1", 42 },
    { "fa0", 43 },
    { "fa1", 44 },
    { "fa2", 45 },
    { "fa3", 46 },
    { "fa4", 47 },
    { "fa5", 48 },
    { "fa6", 49 },
    { "fa7", 50 },
    { "fs2", 51 },
    { "fs3", 52 },
    { "fs4", 53 },
    { "fs5", 54 },
    { "fs6", 55 },
    { "fs7", 56 },
    { "fs8", 57 },
    { "fs9", 58 },
    { "fs10", 59 },
    { "fs11", 60 },
    { "ft8", 61 },
    { "ft9", 62 },
    { "ft10", 63 },
    { "ft11", 64 },
  };

static const struct register_alias riscv_csr_aliases[] =
  {
#define DECLARE_CSR(name, num) { #name, (num) + RISCV_FIRST_CSR_REGNUM },
#include "opcode/riscv-opc.h"

#if RISCV_SCR_CUSTOM_CSR
    DECLARE_CSR(scrmemctl, 0xbd4)

    DECLARE_CSR(scriccmadr, 0xbd8)
    DECLARE_CSR(scriccmsta, 0xbd9)
    DECLARE_CSR(scriccmrd, 0xbda)
    DECLARE_CSR(scriccmwd, 0xbdb)

    DECLARE_CSR(scrmpusel, 0xbc4)
    DECLARE_CSR(scrmpuctl, 0xbc5)
    DECLARE_CSR(scrmpuadr, 0xbc6)
    DECLARE_CSR(scrmpumsk, 0xbc7)
#endif // RISCV_SCR_CUSTOM_CSR
#undef DECLARE_CSR
  };

/* The set and show lists for 'set debug riscv' and 'show debug riscv' prefixes. */

static struct cmd_list_element *setdebugriscvcmdlist = NULL;
static struct cmd_list_element *showdebugriscvcmdlist = NULL;

/* The show callback for the 'show debug riscv' prefix command.  */

static void
show_debug_riscv_command (const char *args, int from_tty)
{
  help_list (showdebugriscvcmdlist, "show debug riscv ", all_commands, gdb_stdout);
}

/* The set callback for the 'set debug riscv' prefix command.  */

static void
set_debug_riscv_command (const char *args, int from_tty)
{
  printf_unfiltered
    (_("\"set debug riscv\" must be followed by an appropriate subcommand.\n"));
  help_list (setdebugriscvcmdlist, "set debug riscv ", all_commands, gdb_stdout);
}

/* The show callback for all 'show debug riscv VARNAME' variables.  */

static void
show_riscv_debug_variable (struct ui_file *file, int from_tty,
			   struct cmd_list_element *c,
			   const char *value)
{
  fprintf_filtered (file,
		    _("riscv debug variable `%s' is set to: %s\n"),
		    c->name, value);
}

/* When this is set to non-zero debugging information about breakpoint
   kinds will be printed.  */

static unsigned int riscv_debug_breakpoints = RISCV_DBG_DFLT;

/* When this is set to non-zero debugging information about inferior calls
   will be printed.  */

static unsigned int riscv_debug_infcall = RISCV_DBG_DFLT;

/* When this is set to non-zero debugging information about stack unwinding
   will be printed.  */

static unsigned int riscv_debug_unwinder = RISCV_DBG_DFLT;

/* When this is set to non-zero debugging information about gdbarch
   initialisation will be printed.  */

static unsigned int riscv_debug_gdbarch = RISCV_DBG_DFLT;

/* See riscv-tdep.h.  */

int
riscv_isa_xlen (struct gdbarch *gdbarch)
{
  return gdbarch_tdep (gdbarch)->isa_features.xlen;
}

/* See riscv-tdep.h.  */

int
riscv_abi_xlen (struct gdbarch *gdbarch)
{
  return gdbarch_tdep (gdbarch)->abi_features.xlen;
}

/* See riscv-tdep.h.  */

int
riscv_isa_flen (struct gdbarch *gdbarch)
{
  return gdbarch_tdep (gdbarch)->isa_features.flen;
}

/* See riscv-tdep.h.  */

int
riscv_abi_flen (struct gdbarch *gdbarch)
{
  return gdbarch_tdep (gdbarch)->abi_features.flen;
}

/* Return true if the target for GDBARCH has floating point hardware.  */

static bool
riscv_has_fp_regs (struct gdbarch *gdbarch)
{
  return (riscv_isa_flen (gdbarch) > 0);
}

/* Return true if GDBARCH is using any of the floating point hardware ABIs.  */

static bool
riscv_has_fp_abi (struct gdbarch *gdbarch)
{
  return gdbarch_tdep (gdbarch)->abi_features.flen > 0;
}

/* Return true if REGNO is a floating pointer register.  */

static bool
riscv_is_fp_regno_p (int regno)
{
  return (regno >= RISCV_FIRST_FP_REGNUM
	  && regno <= RISCV_LAST_FP_REGNUM);
}

/* Implement the breakpoint_kind_from_pc gdbarch method.  */

static int
riscv_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
{
  gdb_byte instr;
  int len;

  /* Read the opcode byte to determine the instruction length.  */
  read_code (*pcptr, &instr, 1);
  len = riscv_insn_length (instr);

  if (riscv_debug_breakpoints)
    {
      fprintf_unfiltered (gdb_stdlog,
			  "Using %sEBREAK for breakpoint at %s\n",
			  len == 2 ? "C." : "",
			  paddress (gdbarch, *pcptr));
    }

  return (len == 2) ? 2 : 4;
}

/* Implement the sw_breakpoint_from_kind gdbarch method.  */

static const gdb_byte *
riscv_sw_breakpoint_from_kind (struct gdbarch *gdbarch, int kind, int *size)
{
  static const gdb_byte ebreak[] = { 0x73, 0x00, 0x10, 0x00, };
  static const gdb_byte c_ebreak[] = { 0x02, 0x90 };

  *size = kind;
  switch (kind)
    {
    case 2:
      return c_ebreak;
    case 4:
      return ebreak;
    default:
      gdb_assert_not_reached (_("unhandled breakpoint kind"));
    }
}

/* Callback function for user_reg_add.  */

static struct value *
value_of_riscv_user_reg (struct frame_info *frame, const void *baton)
{
  const int *reg_p = (const int *) baton;
  return value_of_register (*reg_p, frame);
}

/* Construct the floating point types */

static struct type *
riscv_fpreg_type_float (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->riscv_fpreg_f_type == nullptr)
    {
      struct type *t;
      const struct builtin_type *bt = builtin_type (gdbarch);

      t = arch_composite_type (gdbarch,
			       "__riscv_builtin_type_float_single",
			       TYPE_CODE_UNION);
      append_composite_type_field (t, "float", bt->builtin_float);
      append_composite_type_field (t, "u32", bt->builtin_uint32);
      TYPE_NAME (t) = "riscv_builtin_type_float_single";
      tdep->riscv_fpreg_f_type = t;
    }

  return tdep->riscv_fpreg_f_type;
}

static struct type *
riscv_fpreg_type_double (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->riscv_fpreg_d_type == nullptr)
    {
      struct type *t;
      const struct builtin_type *bt = builtin_type (gdbarch);

      t = arch_composite_type (gdbarch,
			       "__riscv_builtin_type_float",
			       TYPE_CODE_UNION);
      append_composite_type_field (t, "double", bt->builtin_double);
      append_composite_type_field (t, "float", bt->builtin_float);
      append_composite_type_field (t, "u64", bt->builtin_uint64);
      append_composite_type_field (t, "u32", bt->builtin_uint32);
      TYPE_NAME (t) = "riscv_builtin_type_float";
      tdep->riscv_fpreg_d_type = t;
    }

  return tdep->riscv_fpreg_d_type;
}

/* Construct virtual priv mode type */

static struct type *
riscv_priv_type_mode (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  static const char *const sprv[] =
    {
      "[User]",
      "[Supervisor]",
      "[Hypervisor]",
      "[Machine]"
    };

  if (tdep->riscv_priv_type == nullptr)
    {
      struct type *t;

      t = arch_type (gdbarch, TYPE_CODE_ENUM, TARGET_CHAR_BIT, NULL);

      TYPE_NFIELDS (t) = ARRAY_SIZE (sprv);
      TYPE_FIELDS (t) = (struct field *)
	TYPE_ZALLOC (t, ARRAY_SIZE (sprv) * sizeof (struct field));

      for (int i = 0; i < ARRAY_SIZE (sprv); ++i)
	{
	  TYPE_FIELD_NAME (t, i) = xstrdup (sprv[i]);
	  TYPE_FIELD_TYPE (t, i) = NULL;
	  SET_FIELD_ENUMVAL (TYPE_FIELD (t, i), i);
	  TYPE_FIELD_BITSIZE (t, i) = 0;
	}

      TYPE_NAME (t) = "riscv_builtin_type_priv_mode";
      TYPE_UNSIGNED (t) = 1;
      tdep->riscv_priv_type = t;
    }

  return tdep->riscv_priv_type;
}

/* Implement the register_type gdbarch method.  */

static struct type *
riscv_register_type (struct gdbarch *gdbarch, int regnum)
{
  struct type *type = tdesc_register_type (gdbarch, regnum);
  int xlen = riscv_isa_xlen (gdbarch);

  // DBG_PRINT("riscv_register_type(): regnum %d", regnum);

  if (regnum < RISCV_FIRST_FP_REGNUM)
    {
      if (TYPE_CODE (type) == TYPE_CODE_INT && TYPE_LENGTH (type) == xlen)
	{
	  switch (regnum)
	    {
	    case RISCV_PC_REGNUM:
	    case RISCV_RA_REGNUM:
	      return builtin_type (gdbarch)->builtin_func_ptr;
	    case RISCV_SP_REGNUM:
	    case RISCV_GP_REGNUM:
	    case RISCV_TP_REGNUM:
	      return builtin_type (gdbarch)->builtin_data_ptr;
	    }
	}
    }
  else if (regnum <= RISCV_LAST_FP_REGNUM)
    {
      int flen = riscv_isa_flen (gdbarch);

      if (TYPE_CODE (type) == TYPE_CODE_FLT && TYPE_LENGTH (type) == flen)
	{
	  switch (flen)
	    {
	    case 4:
	      return riscv_fpreg_type_float (gdbarch);
	    case 8:
	      return riscv_fpreg_type_double (gdbarch);
	    }
	}
    }
  else if (TYPE_CODE (type) == TYPE_CODE_INT)
    {
      // TODO: mstatus composite type
      // TODO: extended cause type (composite)
      switch (regnum)
	{
	  // extended priv type (enum)
	case RISCV_VIRT_PRIV_REGNUM:
	  return riscv_priv_type_mode (gdbarch);

	  // TODO: extended fflags type
	case RISCV_CSR_FFLAGS_REGNUM:
	case RISCV_CSR_FRM_REGNUM:
	case RISCV_CSR_FCSR_REGNUM:
	  return builtin_type (gdbarch)->builtin_uint32;

	case RISCV_CSR_MEPC_REGNUM:
	case RISCV_CSR_SEPC_REGNUM:
	case RISCV_CSR_UEPC_REGNUM:
	case RISCV_CSR_DPC_REGNUM:
	case RISCV_CSR_MTVEC_REGNUM:
	case RISCV_CSR_STVEC_REGNUM:
	case RISCV_CSR_UTVEC_REGNUM:
	  return builtin_type (gdbarch)->builtin_func_ptr;

	case RISCV_CSR_MTVAL_REGNUM:
	case RISCV_CSR_STVAL_REGNUM:
	case RISCV_CSR_UTVAL_REGNUM: // 0x43
	  return builtin_type (gdbarch)->builtin_data_ptr;
	}
    }

  return type;
}

/* RISC-V register groups "csr" and "virtual" */

static struct reggroup *riscv_csr_reggroup;
static struct reggroup *riscv_virt_reggroup;

static void
riscv_init_reggroups (void)
{
  riscv_csr_reggroup = reggroup_new ("csr", USER_REGGROUP);
  riscv_virt_reggroup = reggroup_new ("virtual", USER_REGGROUP);
}

static void
riscv_add_reggroups (struct gdbarch *gdbarch)
{
  /* Add predefined register groups.  */
  reggroup_add (gdbarch, all_reggroup);
  reggroup_add (gdbarch, save_reggroup);
  reggroup_add (gdbarch, restore_reggroup);
  reggroup_add (gdbarch, system_reggroup);
  reggroup_add (gdbarch, vector_reggroup);
  reggroup_add (gdbarch, general_reggroup);
  reggroup_add (gdbarch, float_reggroup);

  /* Add RISC-V specific register groups.  */
  reggroup_add (gdbarch, riscv_csr_reggroup);
  reggroup_add (gdbarch, riscv_virt_reggroup);
}

/* Implement the register_reggroup_p gdbarch method.  */

static int
riscv_register_reggroup_p (struct gdbarch  *gdbarch,
			   int regnum,
			   struct reggroup *reggroup)
{
  unsigned int i;

  // DBG_PRINT("riscv_register_reggroup_p(): regnum %d group %s", regnum, reggroup_name(reggroup));

  /* Used by 'info registers' and 'info registers <groupname>'.  */

  if (gdbarch_register_name (gdbarch, regnum) == NULL
      || gdbarch_register_name (gdbarch, regnum)[0] == '\0')
    return 0;

  if (reggroup == all_reggroup)
    return 1;

  if (reggroup == float_reggroup)
    return (riscv_is_fp_regno_p (regnum)
	    || regnum == RISCV_CSR_FCSR_REGNUM
	    || regnum == RISCV_CSR_FFLAGS_REGNUM
	    || regnum == RISCV_CSR_FRM_REGNUM);
  else if (reggroup == general_reggroup)
    return regnum != RISCV_ZERO_REGNUM && regnum < RISCV_FIRST_FP_REGNUM;
  else if (reggroup == restore_reggroup || reggroup == save_reggroup)
    {
      if (riscv_has_fp_regs (gdbarch))
	return (regnum <= RISCV_LAST_FP_REGNUM
		|| regnum == RISCV_CSR_FCSR_REGNUM
		|| regnum == RISCV_CSR_FFLAGS_REGNUM
		|| regnum == RISCV_CSR_FRM_REGNUM);
      else
	return regnum < RISCV_FIRST_FP_REGNUM;
    }
  else if (reggroup == system_reggroup)
    {
      if (regnum == RISCV_VIRT_PRIV_REGNUM)
	return 1;
      if (regnum < RISCV_FIRST_CSR_REGNUM || regnum > RISCV_LAST_CSR_REGNUM)
	return 0;
      /* Only include CSRs that have aliases.  */
      for (i = 0; i < ARRAY_SIZE (riscv_csr_aliases/*riscv_register_aliases*/); ++i)
	{
	  if (regnum == /*riscv_register_aliases*/riscv_csr_aliases[i].regnum)
	    return 1;
	}
      return 0;
    }
  else if (reggroup == riscv_csr_reggroup)
    return regnum >= RISCV_FIRST_CSR_REGNUM && regnum <= RISCV_LAST_CSR_REGNUM;
  else if (reggroup == riscv_virt_reggroup)
    return regnum == RISCV_VIRT_PRIV_REGNUM;
  else if (reggroup == vector_reggroup)
    return 0;
  else
    internal_error (__FILE__, __LINE__, _("unhandled reggroup"));

  return 0;
}

/* Class that handles one decoded RiscV instruction.  */

class riscv_insn
{
public:

  /* Enum of all the opcodes that GDB cares about during the prologue scan.  */
  enum opcode
    {
      /* Unknown value is used at initialisation time.  */
      UNKNOWN = 0,

      /* These instructions are all the ones we are interested in during the
	 prologue scan.  */
      ADD,
      ADDI,
      ADDIW,
      ADDW,
      AUIPC,
      LUI,
      SD,
      SW,
      /* These are needed for software breakopint support.  */
      JAL,
      JALR,
      BEQ,
      BNE,
      BLT,
      BGE,
      BLTU,
      BGEU,
      /* These are needed for stepping over atomic sequences.  */
      LR,
      SC,

      /* Other instructions are not interesting during the prologue scan, and
	 are ignored.  */
      OTHER
    };

  riscv_insn ()
    : m_length (0),
      m_opcode (OTHER),
      m_rd (0),
      m_rs1 (0),
      m_rs2 (0)
  {
    /* Nothing.  */
  }

  void decode (struct gdbarch *gdbarch, CORE_ADDR pc);

  /* Get the length of the instruction in bytes.  */
  int length () const
  { return m_length; }

  /* Get the opcode for this instruction.  */
  enum opcode opcode () const
  { return m_opcode; }

  /* Get destination register field for this instruction.  This is only
     valid if the OPCODE implies there is such a field for this
     instruction.  */
  int rd () const
  { return m_rd; }

  /* Get the RS1 register field for this instruction.  This is only valid
     if the OPCODE implies there is such a field for this instruction.  */
  int rs1 () const
  { return m_rs1; }

  /* Get the RS2 register field for this instruction.  This is only valid
     if the OPCODE implies there is such a field for this instruction.  */
  int rs2 () const
  { return m_rs2; }

  /* Get the immediate for this instruction in signed form.  This is only
     valid if the OPCODE implies there is such a field for this
     instruction.  */
  int imm_signed () const
  { return m_imm.s; }

private:

  /* Extract 5 bit register field at OFFSET from instruction OPCODE.  */
  int decode_register_index (unsigned long opcode, int offset)
  {
    return (opcode >> offset) & 0x1F;
  }

  /* Extract 5 bit register field at OFFSET from instruction OPCODE.  */
  int decode_register_index_short (unsigned long opcode, int offset)
  {
    return ((opcode >> offset) & 0x7) + 8;
  }

  /* Helper for DECODE, decode 32-bit R-type instruction.  */
  void decode_r_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rd = decode_register_index (ival, OP_SH_RD);
    m_rs1 = decode_register_index (ival, OP_SH_RS1);
    m_rs2 = decode_register_index (ival, OP_SH_RS2);
  }

  /* Helper for DECODE, decode 16-bit compressed R-type instruction.  */
  void decode_cr_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rd = m_rs1 = decode_register_index (ival, OP_SH_CRS1S);
    m_rs2 = decode_register_index (ival, OP_SH_CRS2);
  }

  /* Helper for DECODE, decode 32-bit I-type instruction.  */
  void decode_i_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rd = decode_register_index (ival, OP_SH_RD);
    m_rs1 = decode_register_index (ival, OP_SH_RS1);
    m_imm.s = EXTRACT_ITYPE_IMM (ival);
  }

  /* Helper for DECODE, decode 16-bit compressed I-type instruction.  */
  void decode_ci_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rd = m_rs1 = decode_register_index (ival, OP_SH_CRS1S);
    m_imm.s = EXTRACT_RVC_IMM (ival);
  }

  /* Helper for DECODE, decode 32-bit S-type instruction.  */
  void decode_s_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rs1 = decode_register_index (ival, OP_SH_RS1);
    m_rs2 = decode_register_index (ival, OP_SH_RS2);
    m_imm.s = EXTRACT_STYPE_IMM (ival);
  }

  /* Helper for DECODE, decode 16-bit CS-type instruction.  The immediate
     encoding is different for each CS format instruction, so extracting
     the immediate is left up to the caller, who should pass the extracted
     immediate value through in IMM.  */
  void decode_cs_type_insn (enum opcode opcode, ULONGEST ival, int imm)
  {
    m_opcode = opcode;
    m_imm.s = imm;
    m_rs1 = decode_register_index_short (ival, OP_SH_CRS1S);
    m_rs2 = decode_register_index_short (ival, OP_SH_CRS2S);
  }

  /* Helper for DECODE, decode 16-bit CSS-type instruction.  The immediate
     encoding is different for each CSS format instruction, so extracting
     the immediate is left up to the caller, who should pass the extracted
     immediate value through in IMM.  */
  void decode_css_type_insn (enum opcode opcode, ULONGEST ival, int imm)
  {
    m_opcode = opcode;
    m_imm.s = imm;
    m_rs1 = RISCV_SP_REGNUM;
    /* Not a compressed register number in this case.  */
    m_rs2 = decode_register_index (ival, OP_SH_CRS2);
  }

  /* Helper for DECODE, decode 32-bit U-type instruction.  */
  void decode_u_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rd = decode_register_index (ival, OP_SH_RD);
    m_imm.s = EXTRACT_UTYPE_IMM (ival);
  }

  /* Helper for DECODE, decode 32-bit J-type instruction.  */
  void decode_j_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rd = decode_register_index (ival, OP_SH_RD);
    m_imm.s = EXTRACT_UJTYPE_IMM (ival);
  }

  /* Helper for DECODE, decode 32-bit J-type instruction.  */
  void decode_cj_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_imm.s = EXTRACT_RVC_J_IMM (ival);
  }

  void decode_b_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rs1 = decode_register_index (ival, OP_SH_RS1);
    m_rs2 = decode_register_index (ival, OP_SH_RS2);
    m_imm.s = EXTRACT_SBTYPE_IMM (ival);
  }

  void decode_cb_type_insn (enum opcode opcode, ULONGEST ival)
  {
    m_opcode = opcode;
    m_rs1 = decode_register_index_short (ival, OP_SH_CRS1S);
    m_imm.s = EXTRACT_RVC_B_IMM (ival);
  }

  /* Fetch instruction from target memory at ADDR, return the content of
     the instruction, and update LEN with the instruction length.  */
  static ULONGEST fetch_instruction (struct gdbarch *gdbarch,
				     CORE_ADDR addr, int *len);

  /* The length of the instruction in bytes.  Should be 2 or 4.  */
  int m_length;

  /* The instruction opcode.  */
  enum opcode m_opcode;

  /* The three possible registers an instruction might reference.  Not
     every instruction fills in all of these registers.  Which fields are
     valid depends on the opcode.  The naming of these fields matches the
     naming in the riscv isa manual.  */
  int m_rd;
  int m_rs1;
  int m_rs2;

  /* Possible instruction immediate.  This is only valid if the instruction
     format contains an immediate, not all instruction, whether this is
     valid depends on the opcode.  Despite only having one format for now
     the immediate is packed into a union, later instructions might require
     an unsigned formatted immediate, having the union in place now will
     reduce the need for code churn later.  */
  union riscv_insn_immediate
  {
    riscv_insn_immediate ()
      : s (0)
    {
      /* Nothing.  */
    }

    int s;
  } m_imm;
};

/* Fetch instruction from target memory at ADDR, return the content of the
   instruction, and update LEN with the instruction length.  */

ULONGEST
riscv_insn::fetch_instruction (struct gdbarch *gdbarch,
			       CORE_ADDR addr, int *len)
{
  enum bfd_endian byte_order = gdbarch_byte_order_for_code (gdbarch);
  gdb_byte buf[8];
  int instlen, status;

  /* All insns are at least 16 bits.  */
  status = target_read_memory (addr, buf, 2);
  if (status)
    memory_error (TARGET_XFER_E_IO, addr);

  /* If we need more, grab it now.  */
  instlen = riscv_insn_length (buf[0]);
  gdb_assert (instlen <= sizeof (buf));
  *len = instlen;

  if (instlen > 2)
    {
      status = target_read_memory (addr + 2, buf + 2, instlen - 2);
      if (status)
	memory_error (TARGET_XFER_E_IO, addr + 2);
    }

  return extract_unsigned_integer (buf, instlen, byte_order);
}

/* Fetch from target memory an instruction at PC and decode it.  This can
   throw an error if the memory access fails, callers are responsible for
   handling this error if that is appropriate.  */

void
riscv_insn::decode (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  ULONGEST ival;

  /* Fetch the instruction, and the instructions length.  */
  ival = fetch_instruction (gdbarch, pc, &m_length);

  if (m_length == 4)
    {
      if (is_add_insn (ival))
	decode_r_type_insn (ADD, ival);
      else if (is_addw_insn (ival))
	decode_r_type_insn (ADDW, ival);
      else if (is_addi_insn (ival))
	decode_i_type_insn (ADDI, ival);
      else if (is_addiw_insn (ival))
	decode_i_type_insn (ADDIW, ival);
      else if (is_auipc_insn (ival))
	decode_u_type_insn (AUIPC, ival);
      else if (is_lui_insn (ival))
	decode_u_type_insn (LUI, ival);
      else if (is_sd_insn (ival))
	decode_s_type_insn (SD, ival);
      else if (is_sw_insn (ival))
	decode_s_type_insn (SW, ival);
      else if (is_jal_insn (ival))
	decode_j_type_insn (JAL, ival);
      else if (is_jalr_insn (ival))
	decode_i_type_insn (JALR, ival);
      else if (is_beq_insn (ival))
	decode_b_type_insn (BEQ, ival);
      else if (is_bne_insn (ival))
	decode_b_type_insn (BNE, ival);
      else if (is_blt_insn (ival))
	decode_b_type_insn (BLT, ival);
      else if (is_bge_insn (ival))
	decode_b_type_insn (BGE, ival);
      else if (is_bltu_insn (ival))
	decode_b_type_insn (BLTU, ival);
      else if (is_bgeu_insn (ival))
	decode_b_type_insn (BGEU, ival);
      else if (is_lr_w_insn (ival))
	decode_r_type_insn (LR, ival);
      else if (is_lr_d_insn (ival))
	decode_r_type_insn (LR, ival);
      else if (is_sc_w_insn (ival))
	decode_r_type_insn (SC, ival);
      else if (is_sc_d_insn (ival))
	decode_r_type_insn (SC, ival);
      else
	/* None of the other fields are valid in this case.  */
	m_opcode = OTHER;
    }
  else if (m_length == 2)
    {
      int xlen = riscv_isa_xlen (gdbarch);

      /* C_ADD and C_JALR have the same opcode.  If RS2 is 0, then this is a
	 C_JALR.  So must try to match C_JALR first as it has more bits in
	 mask.  */
      if (is_c_jalr_insn (ival))
	decode_cr_type_insn (JALR, ival);
      else if (is_c_add_insn (ival))
	decode_cr_type_insn (ADD, ival);
      /* C_ADDW is RV64 and RV128 only.  */
      else if (xlen != 4 && is_c_addw_insn (ival))
	decode_cr_type_insn (ADDW, ival);
      else if (is_c_addi_insn (ival))
	decode_ci_type_insn (ADDI, ival);
      /* C_ADDIW and C_JAL have the same opcode.  C_ADDIW is RV64 and RV128
	 only and C_JAL is RV32 only.  */
      else if (xlen != 4 && is_c_addiw_insn (ival))
	decode_ci_type_insn (ADDIW, ival);
      else if (xlen == 4 && is_c_jal_insn (ival))
	decode_cj_type_insn (JAL, ival);
      /* C_ADDI16SP and C_LUI have the same opcode.  If RD is 2, then this is a
	 C_ADDI16SP.  So must try to match C_ADDI16SP first as it has more bits
	 in mask.  */
      else if (is_c_addi16sp_insn (ival))
	{
	  m_opcode = ADDI;
	  m_rd = m_rs1 = decode_register_index (ival, OP_SH_RD);
	  m_imm.s = EXTRACT_RVC_ADDI16SP_IMM (ival);
	}
      else if (is_c_addi4spn_insn (ival))
	{
	  m_opcode = ADDI;
	  m_rd = decode_register_index_short (ival, OP_SH_CRS2S);
	  m_rs1 = RISCV_SP_REGNUM;
	  m_imm.s = EXTRACT_RVC_ADDI4SPN_IMM (ival);
	}
      else if (is_c_lui_insn (ival))
        {
          m_opcode = LUI;
          m_rd = decode_register_index (ival, OP_SH_CRS1S);
          m_imm.s = EXTRACT_RVC_LUI_IMM (ival);
        }
      /* C_SD and C_FSW have the same opcode.  C_SD is RV64 and RV128 only,
	 and C_FSW is RV32 only.  */
      else if (xlen != 4 && is_c_sd_insn (ival))
	decode_cs_type_insn (SD, ival, EXTRACT_RVC_LD_IMM (ival));
      else if (is_c_sw_insn (ival))
	decode_cs_type_insn (SW, ival, EXTRACT_RVC_LW_IMM (ival));
      else if (is_c_swsp_insn (ival))
	decode_css_type_insn (SW, ival, EXTRACT_RVC_SWSP_IMM (ival));
      else if (xlen != 4 && is_c_sdsp_insn (ival))
	decode_css_type_insn (SW, ival, EXTRACT_RVC_SDSP_IMM (ival));
      /* C_JR and C_MV have the same opcode.  If RS2 is 0, then this is a C_JR.
	 So must try to match C_JR first as it ahs more bits in mask.  */
      else if (is_c_jr_insn (ival))
	decode_cr_type_insn (JALR, ival);
      else if (is_c_j_insn (ival))
	decode_cj_type_insn (JAL, ival);
      else if (is_c_beqz_insn (ival))
	decode_cb_type_insn (BEQ, ival);
      else if (is_c_bnez_insn (ival))
	decode_cb_type_insn (BNE, ival);
      else
	/* None of the other fields of INSN are valid in this case.  */
	m_opcode = OTHER;
    }
  else
    internal_error (__FILE__, __LINE__,
		    _("unable to decode %d byte instructions in "
		      "prologue at %s"), m_length,
		    core_addr_to_string (pc));
}

/* The prologue scanner.  This is currently only used for skipping the
   prologue of a function when the DWARF information is not sufficient.
   However, it is written with filling of the frame cache in mind, which
   is why different groups of stack setup instructions are split apart
   during the core of the inner loop.  In the future, the intention is to
   extend this function to fully support building up a frame cache that
   can unwind register values when there is no DWARF information.  */

static CORE_ADDR
riscv_scan_prologue (struct gdbarch *gdbarch,
		     CORE_ADDR start_pc, CORE_ADDR end_pc,
		     struct riscv_unwind_cache *cache)
{
  CORE_ADDR cur_pc, next_pc, after_prologue_pc;
  CORE_ADDR end_prologue_addr = 0;

  /* Find an upper limit on the function prologue using the debug
     information.  If the debug information could not be used to provide
     that bound, then use an arbitrary large number as the upper bound.  */
  after_prologue_pc = skip_prologue_using_sal (gdbarch, start_pc);
  if (after_prologue_pc == 0)
    after_prologue_pc = start_pc + 100;   /* Arbitrary large number.  */
  if (after_prologue_pc < end_pc)
    end_pc = after_prologue_pc;

  pv_t regs[RISCV_NUM_INTEGER_REGS]; /* Number of GPR.  */
  for (int regno = 0; regno < RISCV_NUM_INTEGER_REGS; regno++)
    regs[regno] = pv_register (regno, 0);
  pv_area stack (RISCV_SP_REGNUM, gdbarch_addr_bit (gdbarch));

  if (riscv_debug_unwinder)
    fprintf_unfiltered
      (gdb_stdlog,
       "Prologue scan for function starting at %s (limit %s)\n",
       core_addr_to_string (start_pc),
       core_addr_to_string (end_pc));

  for (next_pc = cur_pc = start_pc; cur_pc < end_pc; cur_pc = next_pc)
    {
      struct riscv_insn insn;

      /* Decode the current instruction, and decide where the next
	 instruction lives based on the size of this instruction.  */
      insn.decode (gdbarch, cur_pc);
      gdb_assert (insn.length () > 0);
      next_pc = cur_pc + insn.length ();

      /* Look for common stack adjustment insns.  */
      if ((insn.opcode () == riscv_insn::ADDI
	   || insn.opcode () == riscv_insn::ADDIW)
	  && insn.rd () == RISCV_SP_REGNUM
	  && insn.rs1 () == RISCV_SP_REGNUM)
	{
	  /* Handle: addi sp, sp, -i
	     or:     addiw sp, sp, -i  */
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs1 () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()]
            = pv_add_constant (regs[insn.rs1 ()], insn.imm_signed ());
	}
      else if ((insn.opcode () == riscv_insn::SW
		|| insn.opcode () == riscv_insn::SD)
	       && (insn.rs1 () == RISCV_SP_REGNUM
		   || insn.rs1 () == RISCV_FP_REGNUM))
	{
	  /* Handle: sw reg, offset(sp)
	     or:     sd reg, offset(sp)
	     or:     sw reg, offset(s0)
	     or:     sd reg, offset(s0)  */
	  /* Instruction storing a register onto the stack.  */
          gdb_assert (insn.rs1 () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs2 () < RISCV_NUM_INTEGER_REGS);
          stack.store (pv_add_constant (regs[insn.rs1 ()], insn.imm_signed ()),
                        (insn.opcode () == riscv_insn::SW ? 4 : 8),
                        regs[insn.rs2 ()]);
	}
      else if (insn.opcode () == riscv_insn::ADDI
	       && insn.rd () == RISCV_FP_REGNUM
	       && insn.rs1 () == RISCV_SP_REGNUM)
	{
	  /* Handle: addi s0, sp, size  */
	  /* Instructions setting up the frame pointer.  */
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs1 () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()]
            = pv_add_constant (regs[insn.rs1 ()], insn.imm_signed ());
	}
      else if ((insn.opcode () == riscv_insn::ADD
		|| insn.opcode () == riscv_insn::ADDW)
	       && insn.rd () == RISCV_FP_REGNUM
	       && insn.rs1 () == RISCV_SP_REGNUM
	       && insn.rs2 () == RISCV_ZERO_REGNUM)
	{
	  /* Handle: add s0, sp, 0
	     or:     addw s0, sp, 0  */
	  /* Instructions setting up the frame pointer.  */
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs1 () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()] = pv_add_constant (regs[insn.rs1 ()], 0);
	}
      else if ((insn.opcode () == riscv_insn::ADDI
                && insn.rd () == RISCV_ZERO_REGNUM
                && insn.rs1 () == RISCV_ZERO_REGNUM
                && insn.imm_signed () == 0))
	{
	  /* Handle: add x0, x0, 0   (NOP)  */
	}
      else if (insn.opcode () == riscv_insn::AUIPC)
        {
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()] = pv_constant (cur_pc + insn.imm_signed ());
        }
      else if (insn.opcode () == riscv_insn::LUI)
        {
	  /* Handle: lui REG, n
             Where REG is not gp register.  */
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()] = pv_constant (insn.imm_signed ());
        }
      else if (insn.opcode () == riscv_insn::ADDI)
        {
          /* Handle: addi REG1, REG2, IMM  */
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs1 () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()]
            = pv_add_constant (regs[insn.rs1 ()], insn.imm_signed ());
        }
      else if (insn.opcode () == riscv_insn::ADD)
        {
          /* Handle: addi REG1, REG2, IMM  */
          gdb_assert (insn.rd () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs1 () < RISCV_NUM_INTEGER_REGS);
          gdb_assert (insn.rs2 () < RISCV_NUM_INTEGER_REGS);
          regs[insn.rd ()] = pv_add (regs[insn.rs1 ()], regs[insn.rs2 ()]);
        }
      else
	{
	  end_prologue_addr = cur_pc;
	  break;
	}
    }

  if (end_prologue_addr == 0)
    end_prologue_addr = cur_pc;

  if (riscv_debug_unwinder)
    fprintf_unfiltered (gdb_stdlog, "End of prologue at %s\n",
			core_addr_to_string (end_prologue_addr));

  if (cache != NULL)
    {
      /* Figure out if it is a frame pointer or just a stack pointer.  Also
         the offset held in the pv_t is from the original register value to
         the current value, which for a grows down stack means a negative
         value.  The FRAME_BASE_OFFSET is the negation of this, how to get
         from the current value to the original value.  */
      if (pv_is_register (regs[RISCV_FP_REGNUM], RISCV_SP_REGNUM))
	{
          cache->frame_base_reg = RISCV_FP_REGNUM;
          cache->frame_base_offset = -regs[RISCV_FP_REGNUM].k;
	}
      else
	{
          cache->frame_base_reg = RISCV_SP_REGNUM;
          cache->frame_base_offset = -regs[RISCV_SP_REGNUM].k;
	}

      /* Assign offset from old SP to all saved registers.  As we don't
         have the previous value for the frame base register at this
         point, we store the offset as the address in the trad_frame, and
         then convert this to an actual address later.  */
      for (int i = 0; i <= RISCV_NUM_INTEGER_REGS; i++)
	{
	  CORE_ADDR offset;
	  if (stack.find_reg (gdbarch, i, &offset))
            {
              if (riscv_debug_unwinder)
		{
		  /* Display OFFSET as a signed value, the offsets are from
		     the frame base address to the registers location on
		     the stack, with a descending stack this means the
		     offsets are always negative.  */
		  fprintf_unfiltered (gdb_stdlog,
				      "Register $%s at stack offset %s\n",
				      gdbarch_register_name (gdbarch, i),
				      plongest ((LONGEST) offset));
		}
              trad_frame_set_addr (cache->regs, i, offset);
            }
	}
    }

  return end_prologue_addr;
}

/* Implement the riscv_skip_prologue gdbarch method.  */

static CORE_ADDR
riscv_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr;

  /* See if we can determine the end of the prologue via the symbol
     table.  If so, then return either PC, or the PC after the
     prologue, whichever is greater.  */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc
	= skip_prologue_using_sal (gdbarch, func_addr);

      if (post_prologue_pc != 0)
	return std::max (pc, post_prologue_pc);
    }

  /* Can't determine prologue from the symbol table, need to examine
     instructions.  Pass -1 for the end address to indicate the prologue
     scanner can scan as far as it needs to find the end of the prologue.  */
  return riscv_scan_prologue (gdbarch, pc, ((CORE_ADDR) -1), NULL);
}

/* Implement the gdbarch push dummy code callback.  */

static CORE_ADDR
riscv_push_dummy_code (struct gdbarch *gdbarch, CORE_ADDR sp,
		       CORE_ADDR funaddr, struct value **args, int nargs,
		       struct type *value_type, CORE_ADDR *real_pc,
		       CORE_ADDR *bp_addr, struct regcache *regcache)
{
  /* Allocate space for a breakpoint, and keep the stack correctly
     aligned.  */
  sp -= 16;
  *bp_addr = sp;
  *real_pc = funaddr;
  return sp;
}

/* Compute the alignment of the type T.  Used while setting up the
   arguments for a dummy call.  */

static int
riscv_type_alignment (struct type *t)
{
  t = check_typedef (t);
  switch (TYPE_CODE (t))
    {
    default:
      error (_("Could not compute alignment of type"));

    case TYPE_CODE_RVALUE_REF:
    case TYPE_CODE_PTR:
    case TYPE_CODE_ENUM:
    case TYPE_CODE_INT:
    case TYPE_CODE_FLT:
    case TYPE_CODE_REF:
    case TYPE_CODE_CHAR:
    case TYPE_CODE_BOOL:
      return TYPE_LENGTH (t);

    case TYPE_CODE_ARRAY:
      if (TYPE_VECTOR (t))
	return std::min (TYPE_LENGTH (t), (unsigned) BIGGEST_ALIGNMENT);
      /* FALLTHROUGH */

    case TYPE_CODE_COMPLEX:
      return riscv_type_alignment (TYPE_TARGET_TYPE (t));

    case TYPE_CODE_STRUCT:
    case TYPE_CODE_UNION:
      {
	int i;
	int align = 1;

	for (i = 0; i < TYPE_NFIELDS (t); ++i)
	  {
	    if (TYPE_FIELD_LOC_KIND (t, i) == FIELD_LOC_KIND_BITPOS)
	      {
		int a = riscv_type_alignment (TYPE_FIELD_TYPE (t, i));
		if (a > align)
		  align = a;
	      }
	  }
	return align;
      }
    }
}

/* Holds information about a single argument either being passed to an
   inferior function, or returned from an inferior function.  This includes
   information about the size, type, etc of the argument, and also
   information about how the argument will be passed (or returned).  */

struct riscv_arg_info
{
  /* Contents of the argument.  */
  const gdb_byte *contents;

  /* Length of argument.  */
  int length;

  /* Alignment required for an argument of this type.  */
  int align;

  /* The type for this argument.  */
  struct type *type;

  /* Each argument can have either 1 or 2 locations assigned to it.  Each
     location describes where part of the argument will be placed.  The
     second location is valid based on the LOC_TYPE and C_LENGTH fields
     of the first location (which is always valid).  */
  struct location
  {
    /* What type of location this is.  */
    enum location_type
      {
       /* Argument passed in a register.  */
       in_reg,

       /* Argument passed as an on stack argument.  */
       on_stack,

       /* Argument passed by reference.  The second location is always
	  valid for a BY_REF argument, and describes where the address
	  of the BY_REF argument should be placed.  */
       by_ref
      } loc_type;

    /* Information that depends on the location type.  */
    union
    {
      /* Which register number to use.  */
      int regno;

      /* The offset into the stack region.  */
      int offset;
    } loc_data;

    /* The length of contents covered by this location.  If this is less
       than the total length of the argument, then the second location
       will be valid, and will describe where the rest of the argument
       will go.  */
    int c_length;

    /* The offset within CONTENTS for this part of the argument.  Will
       always be 0 for the first part.  For the second part of the
       argument, this might be the C_LENGTH value of the first part,
       however, if we are passing a structure in two registers, and there's
       is padding between the first and second field, then this offset
       might be greater than the length of the first argument part.  When
       the second argument location is not holding part of the argument
       value, but is instead holding the address of a reference argument,
       then this offset will be set to 0.  */
    int c_offset;
  } argloc[2];

  /* TRUE if this is an unnamed argument.  */
  bool is_unnamed;
};

/* Information about a set of registers being used for passing arguments as
   part of a function call.  The register set must be numerically
   sequential from NEXT_REGNUM to LAST_REGNUM.  The register set can be
   disabled from use by setting NEXT_REGNUM greater than LAST_REGNUM.  */

struct riscv_arg_reg
{
  riscv_arg_reg (int first, int last)
    : next_regnum (first),
      last_regnum (last)
  {
    /* Nothing.  */
  }

  /* The GDB register number to use in this set.  */
  int next_regnum;

  /* The last GDB register number to use in this set.  */
  int last_regnum;
};

/* Arguments can be passed as on stack arguments, or by reference.  The
   on stack arguments must be in a continuous region starting from $sp,
   while the by reference arguments can be anywhere, but we'll put them
   on the stack after (at higher address) the on stack arguments.

   This might not be the right approach to take.  The ABI is clear that
   an argument passed by reference can be modified by the callee, which
   us placing the argument (temporarily) onto the stack will not achieve
   (changes will be lost).  There's also the possibility that very large
   arguments could overflow the stack.

   This struct is used to track offset into these two areas for where
   arguments are to be placed.  */
struct riscv_memory_offsets
{
  riscv_memory_offsets ()
    : arg_offset (0),
      ref_offset (0)
  {
    /* Nothing.  */
  }

  /* Offset into on stack argument area.  */
  int arg_offset;

  /* Offset into the pass by reference area.  */
  int ref_offset;
};

/* Holds information about where arguments to a call will be placed.  This
   is updated as arguments are added onto the call, and can be used to
   figure out where the next argument should be placed.  */

struct riscv_call_info
{
  riscv_call_info (struct gdbarch *gdbarch)
    : int_regs (RISCV_A0_REGNUM, RISCV_A0_REGNUM + 7),
      float_regs (RISCV_FA0_REGNUM, RISCV_FA0_REGNUM + 7)
  {
    xlen = riscv_abi_xlen (gdbarch);
    flen = riscv_abi_flen (gdbarch);

    /* Disable use of floating point registers if needed.  */
    if (!riscv_has_fp_abi (gdbarch))
      float_regs.next_regnum = float_regs.last_regnum + 1;
  }

  /* Track the memory areas used for holding in-memory arguments to a
     call.  */
  struct riscv_memory_offsets memory;

  /* Holds information about the next integer register to use for passing
     an argument.  */
  struct riscv_arg_reg int_regs;

  /* Holds information about the next floating point register to use for
     passing an argument.  */
  struct riscv_arg_reg float_regs;

  /* The XLEN and FLEN are copied in to this structure for convenience, and
     are just the results of calling RISCV_ABI_XLEN and RISCV_ABI_FLEN.  */
  int xlen;
  int flen;
};

/* Return the number of registers available for use as parameters in the
   register set REG.  Returned value can be 0 or more.  */

static int
riscv_arg_regs_available (struct riscv_arg_reg *reg)
{
  if (reg->next_regnum > reg->last_regnum)
    return 0;

  return (reg->last_regnum - reg->next_regnum + 1);
}

/* If there is at least one register available in the register set REG then
   the next register from REG is assigned to LOC and the length field of
   LOC is updated to LENGTH.  The register set REG is updated to indicate
   that the assigned register is no longer available and the function
   returns true.

   If there are no registers available in REG then the function returns
   false, and LOC and REG are unchanged.  */

static bool
riscv_assign_reg_location (struct riscv_arg_info::location *loc,
			   struct riscv_arg_reg *reg,
			   int length, int offset)
{
  if (reg->next_regnum <= reg->last_regnum)
    {
      loc->loc_type = riscv_arg_info::location::in_reg;
      loc->loc_data.regno = reg->next_regnum;
      reg->next_regnum++;
      loc->c_length = length;
      loc->c_offset = offset;
      return true;
    }

  return false;
}

/* Assign LOC a location as the next stack parameter, and update MEMORY to
   record that an area of stack has been used to hold the parameter
   described by LOC.

   The length field of LOC is updated to LENGTH, the length of the
   parameter being stored, and ALIGN is the alignment required by the
   parameter, which will affect how memory is allocated out of MEMORY.  */

static void
riscv_assign_stack_location (struct riscv_arg_info::location *loc,
			     struct riscv_memory_offsets *memory,
			     int length, int align)
{
  loc->loc_type = riscv_arg_info::location::on_stack;
  memory->arg_offset
    = align_up (memory->arg_offset, align);
  loc->loc_data.offset = memory->arg_offset;
  memory->arg_offset += length;
  loc->c_length = length;

  /* Offset is always 0, either we're the first location part, in which
     case we're reading content from the start of the argument, or we're
     passing the address of a reference argument, so 0.  */
  loc->c_offset = 0;
}

/* Update AINFO, which describes an argument that should be passed or
   returned using the integer ABI.  The argloc fields within AINFO are
   updated to describe the location in which the argument will be passed to
   a function, or returned from a function.

   The CINFO structure contains the ongoing call information, the holds
   information such as which argument registers are remaining to be
   assigned to parameter, and how much memory has been used by parameters
   so far.

   By examining the state of CINFO a suitable location can be selected,
   and assigned to AINFO.  */

static void
riscv_call_arg_scalar_int (struct riscv_arg_info *ainfo,
			   struct riscv_call_info *cinfo)
{
  if (ainfo->length > (2 * cinfo->xlen))
    {
      /* Argument is going to be passed by reference.  */
      ainfo->argloc[0].loc_type
	= riscv_arg_info::location::by_ref;
      cinfo->memory.ref_offset
	= align_up (cinfo->memory.ref_offset, ainfo->align);
      ainfo->argloc[0].loc_data.offset = cinfo->memory.ref_offset;
      cinfo->memory.ref_offset += ainfo->length;
      ainfo->argloc[0].c_length = ainfo->length;

      /* The second location for this argument is given over to holding the
	 address of the by-reference data.  Pass 0 for the offset as this
	 is not part of the actual argument value.  */
      if (!riscv_assign_reg_location (&ainfo->argloc[1],
				      &cinfo->int_regs,
				      cinfo->xlen, 0))
	riscv_assign_stack_location (&ainfo->argloc[1],
				     &cinfo->memory, cinfo->xlen,
				     cinfo->xlen);
    }
  else
    {
      int len = std::min (ainfo->length, cinfo->xlen);
      int align = std::max (ainfo->align, cinfo->xlen);

      /* Unnamed arguments in registers that require 2*XLEN alignment are
	 passed in an aligned register pair.  */
      if (ainfo->is_unnamed && (align == cinfo->xlen * 2)
	  && cinfo->int_regs.next_regnum & 1)
	cinfo->int_regs.next_regnum++;

      if (!riscv_assign_reg_location (&ainfo->argloc[0],
				      &cinfo->int_regs, len, 0))
	riscv_assign_stack_location (&ainfo->argloc[0],
				     &cinfo->memory, len, align);

      if (len < ainfo->length)
	{
	  len = ainfo->length - len;
	  if (!riscv_assign_reg_location (&ainfo->argloc[1],
					  &cinfo->int_regs, len,
					  cinfo->xlen))
	    riscv_assign_stack_location (&ainfo->argloc[1],
					 &cinfo->memory, len, cinfo->xlen);
	}
    }
}

/* Like RISCV_CALL_ARG_SCALAR_INT, except the argument described by AINFO
   is being passed with the floating point ABI.  */

static void
riscv_call_arg_scalar_float (struct riscv_arg_info *ainfo,
			     struct riscv_call_info *cinfo)
{
  if (ainfo->length > cinfo->flen || ainfo->is_unnamed)
    return riscv_call_arg_scalar_int (ainfo, cinfo);
  else
    {
      if (!riscv_assign_reg_location (&ainfo->argloc[0],
				      &cinfo->float_regs,
				      ainfo->length, 0))
	return riscv_call_arg_scalar_int (ainfo, cinfo);
    }
}

/* Like RISCV_CALL_ARG_SCALAR_INT, except the argument described by AINFO
   is a complex floating point argument, and is therefore handled
   differently to other argument types.  */

static void
riscv_call_arg_complex_float (struct riscv_arg_info *ainfo,
			      struct riscv_call_info *cinfo)
{
  if (ainfo->length <= (2 * cinfo->flen)
      && riscv_arg_regs_available (&cinfo->float_regs) >= 2
      && !ainfo->is_unnamed)
    {
      bool result;
      int len = ainfo->length / 2;

      result = riscv_assign_reg_location (&ainfo->argloc[0],
					  &cinfo->float_regs, len, len);
      gdb_assert (result);

      result = riscv_assign_reg_location (&ainfo->argloc[1],
					  &cinfo->float_regs, len, len);
      gdb_assert (result);
    }
  else
    return riscv_call_arg_scalar_int (ainfo, cinfo);
}

/* A structure used for holding information about a structure type within
   the inferior program.  The RiscV ABI has special rules for handling some
   structures with a single field or with two fields.  The counting of
   fields here is done after flattening out all nested structures.  */

class riscv_struct_info
{
public:
  riscv_struct_info ()
    : m_number_of_fields (0),
      m_types { nullptr, nullptr }
  {
    /* Nothing.  */
  }

  /* Analyse TYPE descending into nested structures, count the number of
     scalar fields and record the types of the first two fields found.  */
  void analyse (struct type *type);

  /* The number of scalar fields found in the analysed type.  This is
     currently only accurate if the value returned is 0, 1, or 2 as the
     analysis stops counting when the number of fields is 3.  This is
     because the RiscV ABI only has special cases for 1 or 2 fields,
     anything else we just don't care about.  */
  int number_of_fields () const
  { return m_number_of_fields; }

  /* Return the type for scalar field INDEX within the analysed type.  Will
     return nullptr if there is no field at that index.  Only INDEX values
     0 and 1 can be requested as the RiscV ABI only has special cases for
     structures with 1 or 2 fields.  */
  struct type *field_type (int index) const
  {
    gdb_assert (index < (sizeof (m_types) / sizeof (m_types[0])));
    return m_types[index];
  }

private:
  /* The number of scalar fields found within the structure after recursing
     into nested structures.  */
  int m_number_of_fields;

  /* The types of the first two scalar fields found within the structure
     after recursing into nested structures.  */
  struct type *m_types[2];
};

/* Analyse TYPE descending into nested structures, count the number of
   scalar fields and record the types of the first two fields found.  */

void
riscv_struct_info::analyse (struct type *type)
{
  unsigned int count = TYPE_NFIELDS (type);
  unsigned int i;

  for (i = 0; i < count; ++i)
    {
      if (TYPE_FIELD_LOC_KIND (type, i) != FIELD_LOC_KIND_BITPOS)
	continue;

      struct type *field_type = TYPE_FIELD_TYPE (type, i);
      field_type = check_typedef (field_type);

      switch (TYPE_CODE (field_type))
	{
	case TYPE_CODE_STRUCT:
	  analyse (field_type);
	  break;

	default:
	  /* RiscV only flattens out structures.  Anything else does not
	     need to be flattened, we just record the type, and when we
	     look at the analysis results we'll realise this is not a
	     structure we can special case, and pass the structure in
	     memory.  */
	  if (m_number_of_fields < 2)
	    m_types[m_number_of_fields] = field_type;
	  m_number_of_fields++;
	  break;
	}

      /* RiscV only has special handling for structures with 1 or 2 scalar
	 fields, any more than that and the structure is just passed in
	 memory.  We can safely drop out early when we find 3 or more
	 fields then.  */

      if (m_number_of_fields > 2)
	return;
    }
}

/* Like RISCV_CALL_ARG_SCALAR_INT, except the argument described by AINFO
   is a structure.  Small structures on RiscV have some special case
   handling in order that the structure might be passed in register.
   Larger structures are passed in memory.  After assigning location
   information to AINFO, CINFO will have been updated.  */

static void
riscv_call_arg_struct (struct riscv_arg_info *ainfo,
		       struct riscv_call_info *cinfo)
{
  if (riscv_arg_regs_available (&cinfo->float_regs) >= 1)
    {
      struct riscv_struct_info sinfo;

      sinfo.analyse (ainfo->type);
      if (sinfo.number_of_fields () == 1
	  && TYPE_CODE (sinfo.field_type (0)) == TYPE_CODE_COMPLEX)
	{
	  gdb_assert (TYPE_LENGTH (ainfo->type)
		      == TYPE_LENGTH (sinfo.field_type (0)));
	  return riscv_call_arg_complex_float (ainfo, cinfo);
	}

      if (sinfo.number_of_fields () == 1
	  && TYPE_CODE (sinfo.field_type (0)) == TYPE_CODE_FLT)
	{
	  gdb_assert (TYPE_LENGTH (ainfo->type)
		      == TYPE_LENGTH (sinfo.field_type (0)));
	  return riscv_call_arg_scalar_float (ainfo, cinfo);
	}

      if (sinfo.number_of_fields () == 2
	  && TYPE_CODE (sinfo.field_type (0)) == TYPE_CODE_FLT
	  && TYPE_LENGTH (sinfo.field_type (0)) <= cinfo->flen
	  && TYPE_CODE (sinfo.field_type (1)) == TYPE_CODE_FLT
	  && TYPE_LENGTH (sinfo.field_type (1)) <= cinfo->flen
	  && riscv_arg_regs_available (&cinfo->float_regs) >= 2)
	{
	  int len0, len1, offset;

	  gdb_assert (TYPE_LENGTH (ainfo->type) <= (2 * cinfo->flen));

	  len0 = TYPE_LENGTH (sinfo.field_type (0));
	  if (!riscv_assign_reg_location (&ainfo->argloc[0],
					  &cinfo->float_regs, len0, 0))
	    error (_("failed during argument setup"));

	  len1 = TYPE_LENGTH (sinfo.field_type (1));
	  offset = align_up (len0, riscv_type_alignment (sinfo.field_type (1)));
	  gdb_assert (len1 <= (TYPE_LENGTH (ainfo->type)
			       - TYPE_LENGTH (sinfo.field_type (0))));

	  if (!riscv_assign_reg_location (&ainfo->argloc[1],
					  &cinfo->float_regs,
					  len1, offset))
	    error (_("failed during argument setup"));
	  return;
	}

      if (sinfo.number_of_fields () == 2
	  && riscv_arg_regs_available (&cinfo->int_regs) >= 1
	  && (TYPE_CODE (sinfo.field_type (0)) == TYPE_CODE_FLT
	      && TYPE_LENGTH (sinfo.field_type (0)) <= cinfo->flen
	      && is_integral_type (sinfo.field_type (1))
	      && TYPE_LENGTH (sinfo.field_type (1)) <= cinfo->xlen))
	{
	  int len0, len1, offset;

	  len0 = TYPE_LENGTH (sinfo.field_type (0));
	  if (!riscv_assign_reg_location (&ainfo->argloc[0],
					  &cinfo->float_regs, len0, 0))
	    error (_("failed during argument setup"));

	  len1 = TYPE_LENGTH (sinfo.field_type (1));
	  offset = align_up (len0, riscv_type_alignment (sinfo.field_type (1)));
	  gdb_assert (len1 <= cinfo->xlen);
	  if (!riscv_assign_reg_location (&ainfo->argloc[1],
					  &cinfo->int_regs, len1, offset))
	    error (_("failed during argument setup"));
	  return;
	}

      if (sinfo.number_of_fields () == 2
	  && riscv_arg_regs_available (&cinfo->int_regs) >= 1
	  && (is_integral_type (sinfo.field_type (0))
	      && TYPE_LENGTH (sinfo.field_type (0)) <= cinfo->xlen
	      && TYPE_CODE (sinfo.field_type (1)) == TYPE_CODE_FLT
	      && TYPE_LENGTH (sinfo.field_type (1)) <= cinfo->flen))
	{
	  int len0, len1, offset;

	  len0 = TYPE_LENGTH (sinfo.field_type (0));
	  len1 = TYPE_LENGTH (sinfo.field_type (1));
	  offset = align_up (len0, riscv_type_alignment (sinfo.field_type (1)));

	  gdb_assert (len0 <= cinfo->xlen);
	  gdb_assert (len1 <= cinfo->flen);

	  if (!riscv_assign_reg_location (&ainfo->argloc[0],
					  &cinfo->int_regs, len0, 0))
	    error (_("failed during argument setup"));

	  if (!riscv_assign_reg_location (&ainfo->argloc[1],
					  &cinfo->float_regs,
					  len1, offset))
	    error (_("failed during argument setup"));

	  return;
	}
    }

  /* Non of the structure flattening cases apply, so we just pass using
     the integer ABI.  */
  riscv_call_arg_scalar_int (ainfo, cinfo);
}

/* Assign a location to call (or return) argument AINFO, the location is
   selected from CINFO which holds information about what call argument
   locations are available for use next.  The TYPE is the type of the
   argument being passed, this information is recorded into AINFO (along
   with some additional information derived from the type).  IS_UNNAMED
   is true if this is an unnamed (stdarg) argument, this info is also
   recorded into AINFO.

   After assigning a location to AINFO, CINFO will have been updated.  */

static void
riscv_arg_location (struct gdbarch *gdbarch,
		    struct riscv_arg_info *ainfo,
		    struct riscv_call_info *cinfo,
		    struct type *type, bool is_unnamed)
{
  ainfo->type = type;
  ainfo->length = TYPE_LENGTH (ainfo->type);
  ainfo->align = riscv_type_alignment (ainfo->type);
  ainfo->is_unnamed = is_unnamed;
  ainfo->contents = nullptr;

  switch (TYPE_CODE (ainfo->type))
    {
    case TYPE_CODE_INT:
    case TYPE_CODE_BOOL:
    case TYPE_CODE_CHAR:
    case TYPE_CODE_RANGE:
    case TYPE_CODE_ENUM:
    case TYPE_CODE_PTR:
      if (ainfo->length <= cinfo->xlen)
	{
	  ainfo->type = builtin_type (gdbarch)->builtin_long;
	  ainfo->length = cinfo->xlen;
	}
      else if (ainfo->length <= (2 * cinfo->xlen))
	{
	  ainfo->type = builtin_type (gdbarch)->builtin_long_long;
	  ainfo->length = 2 * cinfo->xlen;
	}

      /* Recalculate the alignment requirement.  */
      ainfo->align = riscv_type_alignment (ainfo->type);
      riscv_call_arg_scalar_int (ainfo, cinfo);
      break;

    case TYPE_CODE_FLT:
      riscv_call_arg_scalar_float (ainfo, cinfo);
      break;

    case TYPE_CODE_COMPLEX:
      riscv_call_arg_complex_float (ainfo, cinfo);
      break;

    case TYPE_CODE_STRUCT:
      riscv_call_arg_struct (ainfo, cinfo);
      break;

    default:
      riscv_call_arg_scalar_int (ainfo, cinfo);
      break;
    }
}

/* Used for printing debug information about the call argument location in
   INFO to STREAM.  The addresses in SP_REFS and SP_ARGS are the base
   addresses for the location of pass-by-reference and
   arguments-on-the-stack memory areas.  */

static void
riscv_print_arg_location (ui_file *stream, struct gdbarch *gdbarch,
			  struct riscv_arg_info *info,
			  CORE_ADDR sp_refs, CORE_ADDR sp_args)
{
  fprintf_unfiltered (stream, "type: '%s', length: 0x%x, alignment: 0x%x",
		      TYPE_SAFE_NAME (info->type), info->length, info->align);
  switch (info->argloc[0].loc_type)
    {
    case riscv_arg_info::location::in_reg:
      fprintf_unfiltered
	(stream, ", register %s",
	 gdbarch_register_name (gdbarch, info->argloc[0].loc_data.regno));
      if (info->argloc[0].c_length < info->length)
	{
	  switch (info->argloc[1].loc_type)
	    {
	    case riscv_arg_info::location::in_reg:
	      fprintf_unfiltered
		(stream, ", register %s",
		 gdbarch_register_name (gdbarch,
					info->argloc[1].loc_data.regno));
	      break;

	    case riscv_arg_info::location::on_stack:
	      fprintf_unfiltered (stream, ", on stack at offset 0x%x",
				  info->argloc[1].loc_data.offset);
	      break;

	    case riscv_arg_info::location::by_ref:
	    default:
	      /* The second location should never be a reference, any
		 argument being passed by reference just places its address
		 in the first location and is done.  */
	      error (_("invalid argument location"));
	      break;
	    }

	  if (info->argloc[1].c_offset > info->argloc[0].c_length)
	    fprintf_unfiltered (stream, " (offset 0x%x)",
				info->argloc[1].c_offset);
	}
      break;

    case riscv_arg_info::location::on_stack:
      fprintf_unfiltered (stream, ", on stack at offset 0x%x",
			  info->argloc[0].loc_data.offset);
      break;

    case riscv_arg_info::location::by_ref:
      fprintf_unfiltered
	(stream, ", by reference, data at offset 0x%x (%s)",
	 info->argloc[0].loc_data.offset,
	 core_addr_to_string (sp_refs + info->argloc[0].loc_data.offset));
      if (info->argloc[1].loc_type
	  == riscv_arg_info::location::in_reg)
	fprintf_unfiltered
	  (stream, ", address in register %s",
	   gdbarch_register_name (gdbarch, info->argloc[1].loc_data.regno));
      else
	{
	  gdb_assert (info->argloc[1].loc_type
		      == riscv_arg_info::location::on_stack);
	  fprintf_unfiltered
	    (stream, ", address on stack at offset 0x%x (%s)",
	     info->argloc[1].loc_data.offset,
	     core_addr_to_string (sp_args + info->argloc[1].loc_data.offset));
	}
      break;

    default:
      gdb_assert_not_reached (_("unknown argument location type"));
    }
}

/* Implement the push dummy call gdbarch callback.  */

static CORE_ADDR
riscv_push_dummy_call (struct gdbarch *gdbarch,
		       struct value *function,
		       struct regcache *regcache,
		       CORE_ADDR bp_addr,
		       int nargs,
		       struct value **args,
		       CORE_ADDR sp,
		       function_call_return_method return_method,
		       CORE_ADDR struct_addr)
{
  int i;
  CORE_ADDR sp_args, sp_refs;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  struct riscv_arg_info *arg_info =
    (struct riscv_arg_info *) alloca (nargs * sizeof (struct riscv_arg_info));

  struct riscv_call_info call_info (gdbarch);

  CORE_ADDR osp = sp;

  struct type *ftype = check_typedef (value_type (function));

  if (TYPE_CODE (ftype) == TYPE_CODE_PTR)
    ftype = check_typedef (TYPE_TARGET_TYPE (ftype));

  /* We'll use register $a0 if we're returning a struct.  */
  if (return_method == return_method_struct)
    ++call_info.int_regs.next_regnum;

  for (i = 0; i < nargs; ++i)
    {
      struct value *arg_value;
      struct type *arg_type;
      struct riscv_arg_info *info = &arg_info[i];

      arg_value = args[i];
      arg_type = check_typedef (value_type (arg_value));

      riscv_arg_location (gdbarch, info, &call_info, arg_type,
			  TYPE_VARARGS (ftype) && i >= TYPE_NFIELDS (ftype));

      if (info->type != arg_type)
	arg_value = value_cast (info->type, arg_value);
      info->contents = value_contents (arg_value);
    }

  /* Adjust the stack pointer and align it.  */
  sp = sp_refs = align_down (sp - call_info.memory.ref_offset, SP_ALIGNMENT);
  sp = sp_args = align_down (sp - call_info.memory.arg_offset, SP_ALIGNMENT);

  if (riscv_debug_infcall > 0)
    {
      fprintf_unfiltered (gdb_stdlog, "dummy call args:\n");
      fprintf_unfiltered (gdb_stdlog, ": floating point ABI %s in use\n",
	       (riscv_has_fp_abi (gdbarch) ? "is" : "is not"));
      fprintf_unfiltered (gdb_stdlog, ": xlen: %d\n: flen: %d\n",
	       call_info.xlen, call_info.flen);
      if (return_method == return_method_struct)
	fprintf_unfiltered (gdb_stdlog,
			    "[*] struct return pointer in register $A0\n");
      for (i = 0; i < nargs; ++i)
	{
	  struct riscv_arg_info *info = &arg_info [i];

	  fprintf_unfiltered (gdb_stdlog, "[%2d] ", i);
	  riscv_print_arg_location (gdb_stdlog, gdbarch, info, sp_refs, sp_args);
	  fprintf_unfiltered (gdb_stdlog, "\n");
	}
      if (call_info.memory.arg_offset > 0
	  || call_info.memory.ref_offset > 0)
	{
	  fprintf_unfiltered (gdb_stdlog, "              Original sp: %s\n",
			      core_addr_to_string (osp));
	  fprintf_unfiltered (gdb_stdlog, "Stack required (for args): 0x%x\n",
			      call_info.memory.arg_offset);
	  fprintf_unfiltered (gdb_stdlog, "Stack required (for refs): 0x%x\n",
			      call_info.memory.ref_offset);
	  fprintf_unfiltered (gdb_stdlog, "          Stack allocated: %s\n",
			      core_addr_to_string_nz (osp - sp));
	}
    }

  /* Now load the argument into registers, or onto the stack.  */

  if (return_method == return_method_struct)
    {
      gdb_byte buf[sizeof (LONGEST)];

      store_unsigned_integer (buf, call_info.xlen, byte_order, struct_addr);
      regcache->cooked_write (RISCV_A0_REGNUM, buf);
    }

  for (i = 0; i < nargs; ++i)
    {
      CORE_ADDR dst;
      int second_arg_length = 0;
      const gdb_byte *second_arg_data;
      struct riscv_arg_info *info = &arg_info [i];

      gdb_assert (info->length > 0);

      switch (info->argloc[0].loc_type)
	{
	case riscv_arg_info::location::in_reg:
	  {
	    gdb_byte tmp [sizeof (ULONGEST)];

	    gdb_assert (info->argloc[0].c_length <= info->length);
	    /* FP values in FP registers must be NaN-boxed.  */
	    if (riscv_is_fp_regno_p (info->argloc[0].loc_data.regno)
		&& info->argloc[0].c_length < call_info.flen)
	      memset (tmp, -1, sizeof (tmp));
	    else
	      memset (tmp, 0, sizeof (tmp));
	    memcpy (tmp, info->contents, info->argloc[0].c_length);
	    regcache->cooked_write (info->argloc[0].loc_data.regno, tmp);
	    second_arg_length =
	      ((info->argloc[0].c_length < info->length)
	       ? info->argloc[1].c_length : 0);
	    second_arg_data = info->contents + info->argloc[1].c_offset;
	  }
	  break;

	case riscv_arg_info::location::on_stack:
	  dst = sp_args + info->argloc[0].loc_data.offset;
	  write_memory (dst, info->contents, info->length);
	  second_arg_length = 0;
	  break;

	case riscv_arg_info::location::by_ref:
	  dst = sp_refs + info->argloc[0].loc_data.offset;
	  write_memory (dst, info->contents, info->length);

	  second_arg_length = call_info.xlen;
	  second_arg_data = (gdb_byte *) &dst;
	  break;

	default:
	  gdb_assert_not_reached (_("unknown argument location type"));
	}

      if (second_arg_length > 0)
	{
	  switch (info->argloc[1].loc_type)
	    {
	    case riscv_arg_info::location::in_reg:
	      {
		gdb_byte tmp [sizeof (ULONGEST)];

		gdb_assert ((riscv_is_fp_regno_p (info->argloc[1].loc_data.regno)
			     && second_arg_length <= call_info.flen)
			    || second_arg_length <= call_info.xlen);
		/* FP values in FP registers must be NaN-boxed.  */
		if (riscv_is_fp_regno_p (info->argloc[1].loc_data.regno)
		    && second_arg_length < call_info.flen)
		  memset (tmp, -1, sizeof (tmp));
		else
		  memset (tmp, 0, sizeof (tmp));
		memcpy (tmp, second_arg_data, second_arg_length);
		regcache->cooked_write (info->argloc[1].loc_data.regno, tmp);
	      }
	      break;

	    case riscv_arg_info::location::on_stack:
	      {
		CORE_ADDR arg_addr;

		arg_addr = sp_args + info->argloc[1].loc_data.offset;
		write_memory (arg_addr, second_arg_data, second_arg_length);
		break;
	      }

	    case riscv_arg_info::location::by_ref:
	    default:
	      /* The second location should never be a reference, any
		 argument being passed by reference just places its address
		 in the first location and is done.  */
	      error (_("invalid argument location"));
	      break;
	    }
	}
    }

  /* Set the dummy return value to bp_addr.
     A dummy breakpoint will be setup to execute the call.  */

  if (riscv_debug_infcall > 0)
    fprintf_unfiltered (gdb_stdlog, ": writing $ra = %s\n",
			core_addr_to_string (bp_addr));
  regcache_cooked_write_unsigned (regcache, RISCV_RA_REGNUM, bp_addr);

  /* Finally, update the stack pointer.  */

  if (riscv_debug_infcall > 0)
    fprintf_unfiltered (gdb_stdlog, ": writing $sp = %s\n",
			core_addr_to_string (sp));
  regcache_cooked_write_unsigned (regcache, RISCV_SP_REGNUM, sp);

  return sp;
}

/* Implement the return_value gdbarch method.  */

static enum return_value_convention
riscv_return_value (struct gdbarch  *gdbarch,
		    struct value *function,
		    struct type *type,
		    struct regcache *regcache,
		    gdb_byte *readbuf,
		    const gdb_byte *writebuf)
{
  struct riscv_call_info call_info (gdbarch);
  struct riscv_arg_info info;
  struct type *arg_type;

  arg_type = check_typedef (type);
  riscv_arg_location (gdbarch, &info, &call_info, arg_type, false);

  if (riscv_debug_infcall > 0)
    {
      fprintf_unfiltered (gdb_stdlog, "riscv return value:\n");
      fprintf_unfiltered (gdb_stdlog, "[R] ");
      riscv_print_arg_location (gdb_stdlog, gdbarch, &info, 0, 0);
      fprintf_unfiltered (gdb_stdlog, "\n");
    }

  if (readbuf != nullptr || writebuf != nullptr)
    {
	unsigned int arg_len;
	struct value *abi_val;
	gdb_byte *old_readbuf = nullptr;
	int regnum;

	/* We only do one thing at a time.  */
	gdb_assert (readbuf == nullptr || writebuf == nullptr);

	/* In some cases the argument is not returned as the declared type,
	   and we need to cast to or from the ABI type in order to
	   correctly access the argument.  When writing to the machine we
	   do the cast here, when reading from the machine the cast occurs
	   later, after extracting the value.  As the ABI type can be
	   larger than the declared type, then the read or write buffers
	   passed in might be too small.  Here we ensure that we are using
	   buffers of sufficient size.  */
	if (writebuf != nullptr)
	  {
	    struct value *arg_val = value_from_contents (arg_type, writebuf);
	    abi_val = value_cast (info.type, arg_val);
	    writebuf = value_contents_raw (abi_val);
	  }
	else
	  {
	    abi_val = allocate_value (info.type);
	    old_readbuf = readbuf;
	    readbuf = value_contents_raw (abi_val);
	  }
	arg_len = TYPE_LENGTH (info.type);

	switch (info.argloc[0].loc_type)
	  {
	    /* Return value in register(s).  */
	  case riscv_arg_info::location::in_reg:
	    {
	      regnum = info.argloc[0].loc_data.regno;
              gdb_assert (info.argloc[0].c_length <= arg_len);
              gdb_assert (info.argloc[0].c_length
			  <= register_size (gdbarch, regnum));

	      if (readbuf)
		regcache->cooked_read_part (regnum, 0,
					    info.argloc[0].c_length,
					    readbuf);

	      if (writebuf)
		regcache->cooked_write_part (regnum, 0,
					     info.argloc[0].c_length,
					     writebuf);

	      /* A return value in register can have a second part in a
		 second register.  */
	      if (info.argloc[0].c_length < info.length)
		{
		  switch (info.argloc[1].loc_type)
		    {
		    case riscv_arg_info::location::in_reg:
		      regnum = info.argloc[1].loc_data.regno;

                      gdb_assert ((info.argloc[0].c_length
				   + info.argloc[1].c_length) <= arg_len);
                      gdb_assert (info.argloc[1].c_length
				  <= register_size (gdbarch, regnum));

		      if (readbuf)
			{
			  readbuf += info.argloc[1].c_offset;
			  regcache->cooked_read_part (regnum, 0,
						      info.argloc[1].c_length,
						      readbuf);
			}

		      if (writebuf)
			{
			  writebuf += info.argloc[1].c_offset;
			  regcache->cooked_write_part (regnum, 0,
						       info.argloc[1].c_length,
						       writebuf);
			}
		      break;

		    case riscv_arg_info::location::by_ref:
		    case riscv_arg_info::location::on_stack:
		    default:
		      error (_("invalid argument location"));
		      break;
		    }
		}
	    }
	    break;

	    /* Return value by reference will have its address in A0.  */
	  case riscv_arg_info::location::by_ref:
	    {
	      ULONGEST addr;

	      regcache_cooked_read_unsigned (regcache, RISCV_A0_REGNUM,
					     &addr);
	      if (readbuf != nullptr)
		read_memory (addr, readbuf, info.length);
	      if (writebuf != nullptr)
		write_memory (addr, writebuf, info.length);
	    }
	    break;

	  case riscv_arg_info::location::on_stack:
	  default:
	    error (_("invalid argument location"));
	    break;
	  }

	/* This completes the cast from abi type back to the declared type
	   in the case that we are reading from the machine.  See the
	   comment at the head of this block for more details.  */
	if (readbuf != nullptr)
	  {
	    struct value *arg_val = value_cast (arg_type, abi_val);
	    memcpy (old_readbuf, value_contents_raw (arg_val),
		    TYPE_LENGTH (arg_type));
	  }
    }

  switch (info.argloc[0].loc_type)
    {
    case riscv_arg_info::location::in_reg:
      return RETURN_VALUE_REGISTER_CONVENTION;
    case riscv_arg_info::location::by_ref:
      return RETURN_VALUE_ABI_RETURNS_ADDRESS;
    case riscv_arg_info::location::on_stack:
    default:
      error (_("invalid argument location"));
    }
}

/* Implement the frame_align gdbarch method.  */

static CORE_ADDR
riscv_frame_align (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  return align_down (addr, 16);
}

/* Implement the unwind_pc gdbarch method.  */

static CORE_ADDR
riscv_unwind_pc (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  return frame_unwind_register_unsigned (next_frame, RISCV_PC_REGNUM);
}

/* Implement the unwind_sp gdbarch method.  */

static CORE_ADDR
riscv_unwind_sp (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  return frame_unwind_register_unsigned (next_frame, RISCV_SP_REGNUM);
}

/* Implement the dummy_id gdbarch method.  */

static struct frame_id
riscv_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_register_unsigned (this_frame, RISCV_SP_REGNUM),
			 get_frame_pc (this_frame));
}

/* Generate, or return the cached frame cache for the RiscV frame
   unwinder.  */

static struct riscv_unwind_cache *
riscv_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  CORE_ADDR pc, start_addr;
  struct riscv_unwind_cache *cache;
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  int numregs, regno;

  if ((*this_cache) != NULL)
    return (struct riscv_unwind_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct riscv_unwind_cache);
  cache->regs = trad_frame_alloc_saved_regs (this_frame);
  (*this_cache) = cache;

  /* Scan the prologue, filling in the cache.  */
  start_addr = get_frame_func (this_frame);
  pc = get_frame_pc (this_frame);
  riscv_scan_prologue (gdbarch, start_addr, pc, cache);

  /* We can now calculate the frame base address.  */
  cache->frame_base
    = (get_frame_register_unsigned (this_frame, cache->frame_base_reg)
       + cache->frame_base_offset);
  if (riscv_debug_unwinder)
    fprintf_unfiltered (gdb_stdlog, "Frame base is %s ($%s + 0x%x)\n",
                        core_addr_to_string (cache->frame_base),
                        gdbarch_register_name (gdbarch,
                                               cache->frame_base_reg),
                        cache->frame_base_offset);

  /* The prologue scanner sets the address of registers stored to the stack
     as the offset of that register from the frame base.  The prologue
     scanner doesn't know the actual frame base value, and so is unable to
     compute the exact address.  We do now know the frame base value, so
     update the address of registers stored to the stack.  */
  numregs = gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch);
  for (regno = 0; regno < numregs; ++regno)
    {
      if (trad_frame_addr_p (cache->regs, regno))
	cache->regs[regno].addr += cache->frame_base;
    }

  /* The previous $pc can be found wherever the $ra value can be found.
     The previous $ra value is gone, this would have been stored be the
     previous frame if required.  */
  cache->regs[gdbarch_pc_regnum (gdbarch)] = cache->regs[RISCV_RA_REGNUM];
  trad_frame_set_unknown (cache->regs, RISCV_RA_REGNUM);

  /* Build the frame id.  */
  cache->this_id = frame_id_build (cache->frame_base, start_addr);

  /* The previous $sp value is the frame base value.  */
  trad_frame_set_value (cache->regs, gdbarch_sp_regnum (gdbarch),
			cache->frame_base);

  return cache;
}

/* Implement the this_id callback for RiscV frame unwinder.  */

static void
riscv_frame_this_id (struct frame_info *this_frame,
		     void **prologue_cache,
		     struct frame_id *this_id)
{
  struct riscv_unwind_cache *cache;

  TRY
    {
      cache = riscv_frame_cache (this_frame, prologue_cache);
      *this_id = cache->this_id;
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      /* Ignore errors, this leaves the frame id as the predefined outer
         frame id which terminates the backtrace at this point.  */
    }
  END_CATCH
}

/* Implement the prev_register callback for RiscV frame unwinder.  */

static struct value *
riscv_frame_prev_register (struct frame_info *this_frame,
			   void **prologue_cache,
			   int regnum)
{
  struct riscv_unwind_cache *cache;

  cache = riscv_frame_cache (this_frame, prologue_cache);
  return trad_frame_get_prev_register (this_frame, cache->regs, regnum);
}

/* Structure defining the RiscV normal frame unwind functions.  Since we
   are the fallback unwinder (DWARF unwinder is used first), we use the
   default frame sniffer, which always accepts the frame.  */

static const struct frame_unwind riscv_frame_unwind =
{
  /*.type          =*/ NORMAL_FRAME,
  /*.stop_reason   =*/ default_frame_unwind_stop_reason,
  /*.this_id       =*/ riscv_frame_this_id,
  /*.prev_register =*/ riscv_frame_prev_register,
  /*.unwind_data   =*/ NULL,
  /*.sniffer       =*/ default_frame_sniffer,
  /*.dealloc_cache =*/ NULL,
  /*.prev_arch     =*/ NULL,
};

/* Extract a set of required target features out of INFO, specifically the
   bfd being executed is examined to see what target features it requires.
   IF there is no current bfd, or the bfd doesn't indicate any useful
   features then a RISCV_GDBARCH_FEATURES is returned in its default state.  */

static struct riscv_gdbarch_features
riscv_features_from_gdbarch_info (const struct gdbarch_info info)
{
  struct riscv_gdbarch_features features;

  /* Now try to improve on the defaults by looking at the binary we are
     going to execute.  We assume the user knows what they are doing and
     that the target will match the binary.  Remember, this code path is
     only used at all if the target hasn't given us a description, so this
     is really a last ditched effort to do something sane before giving
     up.  */
  if (info.abfd != NULL
      && bfd_get_flavour (info.abfd) == bfd_target_elf_flavour)
    {
      unsigned char eclass = elf_elfheader (info.abfd)->e_ident[EI_CLASS];
      int e_flags = elf_elfheader (info.abfd)->e_flags;

      if (eclass == ELFCLASS32)
	features.xlen = 4;
      else if (eclass == ELFCLASS64)
	features.xlen = 8;
      else
	internal_error (__FILE__, __LINE__,
			_("unknown ELF header class %d"), eclass);

      if (e_flags & EF_RISCV_FLOAT_ABI_DOUBLE)
	features.flen = 8;
      else if (e_flags & EF_RISCV_FLOAT_ABI_SINGLE)
	features.flen = 4;

      DBG_PRINT("**RISC-V** riscv_features_from_gdbarch_info: features ELF x/f: %d/%d",
		    features.xlen, features.flen);
    }
  else
    {
#if 0
      const struct bfd_arch_info *binfo = info.bfd_arch_info;

      if (binfo->bits_per_word == 32)
      	features.xlen = 4;
      else if (binfo->bits_per_word == 64)
      	features.xlen = 8;
      else
      	internal_error (__FILE__, __LINE__, _("unknown bits_per_word %d"),
      			binfo->bits_per_word);
#endif // 0/1
      DBG_PRINT("**RISC-V** riscv_features_from_gdbarch_info: features binfo x/f: %d/%d",
		    features.xlen, features.flen);
    }

  return features;
}

#if 0
/* Find a suitable default target description.  Use the contents of INFO,
   specifically the bfd object being executed, to guide the selection of a
   suitable default target description.  */

static const struct target_desc *
riscv_find_default_target_description (const struct gdbarch_info info)
{
  /* Extract desired feature set from INFO.  */
  struct riscv_gdbarch_features features
    = riscv_features_from_gdbarch_info (info);

  /* If the XLEN field is still 0 then we got nothing useful from INFO.  In
     this case we fall back to a minimal useful target, 8-byte x-registers,
     with no floating point.  */
  if (features.xlen == 0)
    features.xlen = 8;

  /* Now build a target description based on the feature set.  */
  return riscv_create_target_description (features);
}
#endif // 0/1

/* Implement the "dwarf2_reg_to_regnum" gdbarch method.  */

static int
riscv_dwarf_reg_to_regnum (struct gdbarch *gdbarch, int reg)
{
  if (reg < RISCV_DWARF_REGNUM_X31)
    return RISCV_ZERO_REGNUM + (reg - RISCV_DWARF_REGNUM_X0);

  else if (reg < RISCV_DWARF_REGNUM_F31)
    return RISCV_FIRST_FP_REGNUM + (reg - RISCV_DWARF_REGNUM_F0);

  return -1;
}

#ifdef RISCV_DBG
static void
riscv_dump_regs (struct gdbarch *gdbarch)
{
  int i;
  char buf[128];
  int maxregs = gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch);

  warning ("riscv gdbarch regs:");

  for (i = 0; i < maxregs; i += 16) {
    int cnt = 0;
    memset (buf, ' ', sizeof(buf));
    for (int n = i; n < maxregs && n < i + 16; ++n) {
      const char *regname = gdbarch_register_name (gdbarch, n);
      if (regname != NULL && regname[0] != '\0') {
	memcpy (buf + (n - i) * 8, regname, strlen (regname));
	++cnt;
      }
    }
    if (cnt > 0) {
      buf[sizeof(buf) - 1] = '\0';
      warning ("%04d: %s", i, buf);
    }
  }
}
#endif // RISCV_DBG

static int
riscv_assign_isa_registers (const struct tdesc_feature *feature,
			    struct tdesc_arch_data *tdesc_data,
			    const char *reg_prefix,
			    int regno_offset,
			    int first_reg,
			    int last_reg)
{
  int valid_p = 1;

  DBG_PRINT("**RISC-V** riscv_assign_isa_registers: \"%s\" %d/%d-%d",
	    reg_prefix, regno_offset, first_reg, last_reg);

  for (int i = first_reg; i <= last_reg; ++i)
    {
      char buf[16];
      xsnprintf (buf, sizeof (buf), "%s%d", reg_prefix, i + regno_offset);
      int res = tdesc_numbered_register(feature,
					tdesc_data,
					i,
					buf);
      if (res)
	DBG_PRINT("**RISC-V** riscv_assign_abi_registers: %-16s    %d",
		  buf, i);
      valid_p &= res;
    }

  return valid_p;
}

static int
riscv_assign_abi_registers (const struct tdesc_feature *feature,
			    struct tdesc_arch_data *tdesc_data,
			    const struct register_alias *reg_alias,
			    int num)
{
  int valid_p = 1;
  int cnt = 0;

  DBG_PRINT("**RISC-V** riscv_assign_abi_registers: \"%s\" ... \"%s\" (%d)",
	    reg_alias->name, reg_alias[num - 1].name, num);

  for (; num > 0; --num, ++reg_alias)
    {
      int res = tdesc_numbered_register(feature,
					 tdesc_data,
					 reg_alias->regnum,
					 reg_alias->name);
      if (res)
	DBG_PRINT("**RISC-V** riscv_assign_abi_registers: %-16s    %d",
		  reg_alias->name, reg_alias->regnum);
      cnt += res;
      valid_p &= res;
    }

  DBG_PRINT("**RISC-V** riscv_assign_abi_registers: assigned %d", cnt);

  return valid_p;
}

/* Add aliases of existing regs */

static void
riscv_add_aliases (struct gdbarch *gdbarch,
		   const struct register_alias *reg_alias,
		   int num)
{
  for (; num > 0; --num, ++reg_alias)
    {
      const char *regname = gdbarch_register_name (gdbarch, reg_alias->regnum);

      if (regname != NULL
	  && regname[0] != '\0'
	  && strcmp(regname, reg_alias->name))
	{
	  user_reg_add (gdbarch, reg_alias->name,
			value_of_riscv_user_reg, &reg_alias->regnum);
	  DBG_PRINT("**RISC-V** add alias: %-16s     %s",
		    reg_alias->name, regname);
	}
    }
}

static struct gdbarch *
riscv_gdbarch_alloc(struct gdbarch_info *info, struct gdbarch_tdep *tdep)
{
  struct gdbarch *gdbarch;

  gdbarch = gdbarch_alloc (info, tdep);

  /* Target data types.  */
  set_gdbarch_short_bit (gdbarch, 16);
  set_gdbarch_int_bit (gdbarch, 32);
  set_gdbarch_long_bit (gdbarch, riscv_isa_xlen (gdbarch) * 8);
  set_gdbarch_long_long_bit (gdbarch, 64);
  set_gdbarch_float_bit (gdbarch, 32);
  set_gdbarch_double_bit (gdbarch, 64);
  set_gdbarch_long_double_bit (gdbarch, 128);
  set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
  set_gdbarch_ptr_bit (gdbarch, riscv_isa_xlen (gdbarch) * 8);
  set_gdbarch_char_signed (gdbarch, 0);

  /* Information about the target architecture.  */
  set_gdbarch_return_value (gdbarch, riscv_return_value);
  set_gdbarch_breakpoint_kind_from_pc (gdbarch, riscv_breakpoint_kind_from_pc);
  set_gdbarch_sw_breakpoint_from_kind (gdbarch, riscv_sw_breakpoint_from_kind);
/*
  "nonsteppable" watchpoint means that watchpoint triggers before
  instruction is committed, therefore it is required to remove watchpoint
  to step though instruction that triggers it.
*/
  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);

  /* Functions to analyze frames.  */
  set_gdbarch_skip_prologue (gdbarch, riscv_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
  set_gdbarch_frame_align (gdbarch, riscv_frame_align);

  /* Functions to access frame data.  */
  set_gdbarch_unwind_pc (gdbarch, riscv_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, riscv_unwind_sp);

  /* Functions handling dummy frames.  */
  set_gdbarch_call_dummy_location (gdbarch, ON_STACK);
  set_gdbarch_push_dummy_code (gdbarch, riscv_push_dummy_code);
  set_gdbarch_push_dummy_call (gdbarch, riscv_push_dummy_call);
  set_gdbarch_dummy_id (gdbarch, riscv_dummy_id);

  /* Frame unwinders.  Use DWARF debug info if available, otherwise use our own
     unwinder.  */
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &riscv_frame_unwind);

  /* Register architecture.  */
  riscv_add_reggroups (gdbarch);

  /* Internal <-> external register number maps.  */
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, riscv_dwarf_reg_to_regnum);

  /* We reserve all possible register numbers for the known registers.
     This means the target description mechanism will add any target
     specific registers after this number.  This helps make debugging GDB
     just a little easier.  */
  set_gdbarch_num_regs (gdbarch, RISCV_VIRT_NUM_REGS);

  /* We don't have to provide the count of 0 here (its the default) but
     include this line to make it explicit that, right now, we don't have
     any pseudo registers on RISC-V.  */
  set_gdbarch_num_pseudo_regs (gdbarch, 0);

  /* Some specific register numbers GDB likes to know about.  */
  set_gdbarch_sp_regnum (gdbarch, RISCV_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, RISCV_PC_REGNUM);
  //  set_gdbarch_ps_regnum (gdbarch, RISCV_FP_REGNUM);
  // set_gdbarch_deprecated_fp_regnum (gdbarch, RISCV_FP_REGNUM);

  set_gdbarch_register_name (gdbarch, tdesc_register_name);
  set_gdbarch_register_type (gdbarch, tdesc_register_type);
  set_gdbarch_register_reggroup_p (gdbarch, riscv_register_reggroup_p);

  if (tdesc_has_registers (info->target_desc))
    {
      /* Finalise the target description registers.  */
      tdesc_use_registers (gdbarch, info->target_desc, info->tdesc_data);

      /* Hook in OS ABI-specific overrides, if they have been registered.  */
      gdbarch_init_osabi (*info, gdbarch);

      /* Override the register name/type/group callbacks */
      // set_gdbarch_register_name (gdbarch, riscv_register_name);
      set_gdbarch_register_type (gdbarch, riscv_register_type);
      set_gdbarch_register_reggroup_p (gdbarch, riscv_register_reggroup_p);
    }
  return gdbarch;
}

static struct gdbarch *
riscv_gdbarch_init (struct gdbarch_info info,
		    struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch = NULL;
  struct gdbarch_tdep *tdep;

  struct riscv_gdbarch_features isa_features, abi_features;

  DBG_PRINT("**RISC-V** riscv_gdbarch_init: tdesc_has_registers = %d",
	    tdesc_has_registers (info.target_desc));
#if 0
  if (!tdesc_has_registers (info.target_desc))
    info.target_desc = riscv_find_default_target_description (info);
#endif // 0/1

  abi_features = riscv_features_from_gdbarch_info(info);

  /* Check any target description for validity.  */
  if (tdesc_has_registers (info.target_desc))
    {
      const struct tdesc_feature *feature_cpu;
      struct tdesc_arch_data *tdesc_data = NULL;

      feature_cpu = tdesc_find_feature (info.target_desc, RISCV_GDB_FEATURE_CPU);
      if (feature_cpu)
	{
	  const struct tdesc_feature *feature_fpu;
	  const struct tdesc_feature *feature_csr;
	  const struct tdesc_feature *feature_virt;
	  int valid_p;

	  tdesc_data = tdesc_data_alloc ();

	  // PC register is required only
	  valid_p = tdesc_numbered_register (feature_cpu, tdesc_data,
					     RISCV_PC_REGNUM,
					     RISCV_PC_REGNAME);

	  if (!valid_p)
	    {
	      if (riscv_debug_gdbarch)
		fprintf_unfiltered (gdb_stdlog, "Target description is not valid\n");
	      tdesc_data_cleanup (tdesc_data);
	      return NULL;
	    }

	  isa_features.xlen =
	    tdesc_register_bitsize (feature_cpu, RISCV_PC_REGNAME) / TARGET_CHAR_BIT;

	  // numbered ISA names (GDB preferred)
	  riscv_assign_isa_registers (feature_cpu,
				      tdesc_data,
				      "x",
				      -RISCV_FIRST_GP_REGNUM,
				      RISCV_FIRST_GP_REGNUM,
				      RISCV_LAST_GP_REGNUM);
	  // numbered ABI names (SiFive style)
	  riscv_assign_abi_registers (feature_cpu,
				      tdesc_data,
				      riscv_xreg_aliases,
				      ARRAY_SIZE (riscv_xreg_aliases));

	  feature_fpu =
	    tdesc_find_feature (info.target_desc, RISCV_GDB_FEATURE_FPU);
	  // legacy workaround: all regs in ".cpu" feature
	  if (feature_fpu == NULL)
	    feature_fpu = feature_cpu;

	  // get isa_features.flen
	  if (tdesc_unnumbered_register (feature_fpu, "f0"))
	    {
	      isa_features.flen =
		tdesc_register_bitsize (feature_fpu, "f0") / TARGET_CHAR_BIT;
	    }
	  else if (tdesc_unnumbered_register (feature_fpu, riscv_freg_aliases[0].name))
	    {
	      isa_features.flen =
		tdesc_register_bitsize (feature_fpu, riscv_freg_aliases[0].name) / TARGET_CHAR_BIT;
	    }
	  else
	    {
	      isa_features.flen = 0;
	    }

	  if (isa_features.flen)
	    {
	      // numbered ISA names (GDB preferred)
	      riscv_assign_isa_registers (feature_fpu,
					  tdesc_data,
					  "f",
					  -RISCV_FIRST_FP_REGNUM,
					  RISCV_FIRST_FP_REGNUM,
					  RISCV_LAST_FP_REGNUM);
	      // numbered ABI names (SiFive style)
	      riscv_assign_abi_registers (feature_fpu,
					  tdesc_data,
					  riscv_freg_aliases,
					  ARRAY_SIZE (riscv_freg_aliases));
	      // FPU control/status registers (fcsr,frm,fflags) may be defined in fpu feature
	      tdesc_numbered_register(feature_fpu,
				      tdesc_data,
				      RISCV_CSR_FFLAGS_REGNUM,
				      riscv_csr_aliases[RISCV_FIRST_CSR_REGNUM - RISCV_CSR_FFLAGS_REGNUM].name);
	      tdesc_numbered_register(feature_fpu,
				      tdesc_data,
				      RISCV_CSR_FRM_REGNUM,
				      riscv_csr_aliases[RISCV_FIRST_CSR_REGNUM - RISCV_CSR_FRM_REGNUM].name);
	      tdesc_numbered_register(feature_fpu,
				      tdesc_data,
				      RISCV_CSR_FCSR_REGNUM,
				      riscv_csr_aliases[RISCV_FIRST_CSR_REGNUM - RISCV_CSR_FCSR_REGNUM].name);
	    }

	  feature_csr =
	    tdesc_find_feature (info.target_desc, RISCV_GDB_FEATURE_CSR);
	  if (feature_csr == NULL) // legacy workaround
	    feature_csr = feature_cpu;
	  // numbered ISA names (GDB preferred)
	  riscv_assign_isa_registers (feature_csr,
				      tdesc_data,
				      "csr",
				      -RISCV_FIRST_CSR_REGNUM,
				      RISCV_FIRST_CSR_REGNUM,
				      RISCV_LAST_CSR_REGNUM);
	  // numbered ABI names (SiFive style)
	  riscv_assign_abi_registers (feature_csr,
				      tdesc_data,
				      riscv_csr_aliases,
				      ARRAY_SIZE (riscv_csr_aliases));

	  feature_virt =
	    tdesc_find_feature (info.target_desc, RISCV_GDB_FEATURE_VIRT);
	  if (feature_virt == NULL)
	    feature_virt = feature_cpu;

	  tdesc_numbered_register (feature_virt,
				   tdesc_data,
				   RISCV_VIRT_PRIV_REGNUM,
				   RISCV_VIRT_PRIV_REGNAME);

	  if (abi_features.xlen == 0)
	    abi_features.xlen = isa_features.xlen;

	  if (abi_features.xlen != isa_features.xlen)
	    error (_("bfd requires xlen %d, but target has xlen %d"),
		   abi_features.xlen, isa_features.xlen);
	  if (abi_features.flen > isa_features.flen)
	    error (_("bfd requires flen %d, but target has flen %d"),
		   abi_features.flen, isa_features.flen);

	  /* Update bfd_arch_info */
	  if (info.bfd_arch_info == NULL
	      || info.bfd_arch_info->bits_per_word != isa_features.xlen * TARGET_CHAR_BIT)
	    {
	      DBG_PRINT("**RISC-V** riscv_gdbarch_init: update bfd_arch_info (info %p bits %d)",
			info.bfd_arch_info, info.bfd_arch_info ? info.bfd_arch_info->bits_per_word : 0);
	      info.bfd_arch_info =
		bfd_scan_arch (isa_features.xlen == 4 ?
			       "riscv:rv32" :  "riscv:rv64");
	    }

	  DBG_PRINT("**RISC-V** riscv_gdbarch_init: features x/f isa:%d/%d, abi:%d/%d",
		    isa_features.xlen, isa_features.flen, abi_features.xlen, abi_features.flen);

	  /* Find a candidate among the list of pre-declared architectures.  */
	  for (arches = gdbarch_list_lookup_by_info (arches, &info);
	       arches != NULL;
	       arches = gdbarch_list_lookup_by_info (arches->next, &info))
	    {
	      /* Check that the feature set of the ARCHES matches the feature set
		 we are looking for.  If it doesn't then we can't reuse this
		 gdbarch.  */
	      struct gdbarch_tdep *other_tdep = gdbarch_tdep (arches->gdbarch);

	      if (other_tdep->isa_features == isa_features
		  && other_tdep->abi_features == abi_features)
		break;
	    }

	  if (arches != NULL)
	    {
	      DBG_PRINT("**RISC-V** riscv_gdbarch_init: reuse existing gdbarch");
	      tdesc_data_cleanup (tdesc_data);
	      return arches->gdbarch;
	    }

	  /* None found, so create a new architecture from the information provided.
	     Can't initialize all the target dependencies until we actually know which
	     target we are talking to, but put in some defaults for now.  */

	  tdep = new (struct gdbarch_tdep);
	  tdep->isa_features = isa_features;
	  tdep->abi_features = abi_features;
	  info.tdesc_data = tdesc_data;

	  gdbarch = riscv_gdbarch_alloc(&info, tdep);

	  // Add aliases for existing regs
	  riscv_add_aliases(gdbarch, riscv_xreg_aliases, ARRAY_SIZE (riscv_xreg_aliases));
	  riscv_add_aliases(gdbarch, riscv_freg_aliases, ARRAY_SIZE (riscv_freg_aliases));
	  riscv_add_aliases(gdbarch, riscv_csr_aliases, ARRAY_SIZE (riscv_csr_aliases));
	}
#ifdef RISCV_DBG
      riscv_dump_regs(gdbarch);
#endif
    }

  if (gdbarch == NULL)
    {
      /* Try to use first one pre-declared arch */
      arches = gdbarch_list_lookup_by_info (arches, &info);
      if (arches != NULL) {
	DBG_PRINT("**RISC-V** riscv_gdbarch_init: reuse pre-declared gdbarch");
	gdbarch = arches->gdbarch;
      }
    }

  if (gdbarch == NULL)
    {
      // create dummy gdbarch
      int xlen = 0;

      if (info.bfd_arch_info)
	{
	  switch (info.bfd_arch_info->bits_per_word)
	    {
	    case 32:
	      xlen = 4;
	      break;
	    case 64:
	      xlen = 8;
	      break;
	    default:
	      internal_error (__FILE__, __LINE__, _("unknown bits_per_word %d"),
			      info.bfd_arch_info->bits_per_word);
	    }
	}

      DBG_PRINT("**RISC-V** riscv_gdbarch_init: create dummy gdbarch xlen %d", xlen);

      tdep = new (struct gdbarch_tdep);
      tdep->isa_features.xlen = xlen;
      gdbarch = riscv_gdbarch_alloc(&info, tdep);
    }

  return gdbarch;
}

/* This decodes the current instruction and determines the address of the
   next instruction.  */

static CORE_ADDR
riscv_next_pc (struct regcache *regcache, CORE_ADDR pc)
{
  struct gdbarch *gdbarch = regcache->arch ();
  struct riscv_insn insn;
  CORE_ADDR next_pc;

  insn.decode (gdbarch, pc);
  next_pc = pc + insn.length ();

  if (insn.opcode () == riscv_insn::JAL)
    next_pc = pc + insn.imm_signed ();
  else if (insn.opcode () == riscv_insn::JALR)
    {
      LONGEST source;
      regcache->cooked_read (insn.rs1 (), &source);
      next_pc = (source + insn.imm_signed ()) & ~(CORE_ADDR) 0x1;
    }
  else if (insn.opcode () == riscv_insn::BEQ)
    {
      LONGEST src1, src2;
      regcache->cooked_read (insn.rs1 (), &src1);
      regcache->cooked_read (insn.rs2 (), &src2);
      if (src1 == src2)
	next_pc = pc + insn.imm_signed ();
    }
  else if (insn.opcode () == riscv_insn::BNE)
    {
      LONGEST src1, src2;
      regcache->cooked_read (insn.rs1 (), &src1);
      regcache->cooked_read (insn.rs2 (), &src2);
      if (src1 != src2)
	next_pc = pc + insn.imm_signed ();
    }
  else if (insn.opcode () == riscv_insn::BLT)
    {
      LONGEST src1, src2;
      regcache->cooked_read (insn.rs1 (), &src1);
      regcache->cooked_read (insn.rs2 (), &src2);
      if (src1 < src2)
	next_pc = pc + insn.imm_signed ();
    }
  else if (insn.opcode () == riscv_insn::BGE)
    {
      LONGEST src1, src2;
      regcache->cooked_read (insn.rs1 (), &src1);
      regcache->cooked_read (insn.rs2 (), &src2);
      if (src1 >= src2)
	next_pc = pc + insn.imm_signed ();
    }
  else if (insn.opcode () == riscv_insn::BLTU)
    {
      ULONGEST src1, src2;
      regcache->cooked_read (insn.rs1 (), &src1);
      regcache->cooked_read (insn.rs2 (), &src2);
      if (src1 < src2)
	next_pc = pc + insn.imm_signed ();
    }
  else if (insn.opcode () == riscv_insn::BGEU)
    {
      ULONGEST src1, src2;
      regcache->cooked_read (insn.rs1 (), &src1);
      regcache->cooked_read (insn.rs2 (), &src2);
      if (src1 >= src2)
	next_pc = pc + insn.imm_signed ();
    }

  return next_pc;
}

/* We can't put a breakpoint in the middle of a lr/sc atomic sequence, so look
   for the end of the sequence and put the breakpoint there.  */

static bool
riscv_next_pc_atomic_sequence (struct regcache *regcache, CORE_ADDR pc,
			       CORE_ADDR *next_pc)
{
  struct gdbarch *gdbarch = regcache->arch ();
  struct riscv_insn insn;
  CORE_ADDR cur_step_pc = pc;
  CORE_ADDR last_addr = 0;

  /* First instruction has to be a load reserved.  */
  insn.decode (gdbarch, cur_step_pc);
  if (insn.opcode () != riscv_insn::LR)
    return false;
  cur_step_pc = cur_step_pc + insn.length ();

  /* Next instruction should be branch to exit.  */
  insn.decode (gdbarch, cur_step_pc);
  if (insn.opcode () != riscv_insn::BNE)
    return false;
  last_addr = cur_step_pc + insn.imm_signed ();
  cur_step_pc = cur_step_pc + insn.length ();

  /* Next instruction should be store conditional.  */
  insn.decode (gdbarch, cur_step_pc);
  if (insn.opcode () != riscv_insn::SC)
    return false;
  cur_step_pc = cur_step_pc + insn.length ();

  /* Next instruction should be branch to start.  */
  insn.decode (gdbarch, cur_step_pc);
  if (insn.opcode () != riscv_insn::BNE)
    return false;
  if (pc != (cur_step_pc + insn.imm_signed ()))
    return false;
  cur_step_pc = cur_step_pc + insn.length ();

  /* We should now be at the end of the sequence.  */
  if (cur_step_pc != last_addr)
    return false;

  *next_pc = cur_step_pc;
  return true;
}

/* This is called just before we want to resume the inferior, if we want to
   single-step it but there is no hardware or kernel single-step support.  We
   find the target of the coming instruction and breakpoint it.  */

std::vector<CORE_ADDR>
riscv_software_single_step (struct regcache *regcache)
{
  CORE_ADDR pc, next_pc;

  pc = regcache_read_pc (regcache);

  if (riscv_next_pc_atomic_sequence (regcache, pc, &next_pc))
    return {next_pc};

  next_pc = riscv_next_pc (regcache, pc);

  return {next_pc};
}

extern initialize_file_ftype _initialize_riscv_tdep; /* -Wmissing-prototypes */

void
_initialize_riscv_tdep (void)
{
  riscv_init_reggroups ();

  gdbarch_register (bfd_arch_riscv, riscv_gdbarch_init, NULL);

  /* Add root prefix command for all "set debug riscv" and "show debug
     riscv" commands.  */
  add_prefix_cmd ("riscv", no_class, set_debug_riscv_command,
		  _("RISC-V specific debug commands."),
		  &setdebugriscvcmdlist, "set debug riscv ", 0,
		  &setdebuglist);

  add_prefix_cmd ("riscv", no_class, show_debug_riscv_command,
		  _("RISC-V specific debug commands."),
		  &showdebugriscvcmdlist, "show debug riscv ", 0,
		  &showdebuglist);

  add_setshow_zuinteger_cmd ("breakpoints", class_maintenance,
			     &riscv_debug_breakpoints,  _("\
Set riscv breakpoint debugging."), _("\
Show riscv breakpoint debugging."), _("\
When non-zero, print debugging information for the riscv specific parts\n\
of the breakpoint mechanism."),
			     NULL,
			     show_riscv_debug_variable,
			     &setdebugriscvcmdlist, &showdebugriscvcmdlist);

  add_setshow_zuinteger_cmd ("infcall", class_maintenance,
			     &riscv_debug_infcall,  _("\
Set riscv inferior call debugging."), _("\
Show riscv inferior call debugging."), _("\
When non-zero, print debugging information for the riscv specific parts\n\
of the inferior call mechanism."),
			     NULL,
			     show_riscv_debug_variable,
			     &setdebugriscvcmdlist, &showdebugriscvcmdlist);

  add_setshow_zuinteger_cmd ("unwinder", class_maintenance,
			     &riscv_debug_unwinder,  _("\
Set riscv stack unwinding debugging."), _("\
Show riscv stack unwinding debugging."), _("\
When non-zero, print debugging information for the riscv specific parts\n\
of the stack unwinding mechanism."),
			     NULL,
			     show_riscv_debug_variable,
			     &setdebugriscvcmdlist, &showdebugriscvcmdlist);

  add_setshow_zuinteger_cmd ("gdbarch", class_maintenance,
			     &riscv_debug_gdbarch,  _("\
Set riscv gdbarch initialisation debugging."), _("\
Show riscv gdbarch initialisation debugging."), _("\
When non-zero, print debugging information for the riscv gdbarch\n\
initialisation process."),
			     NULL,
			     show_riscv_debug_variable,
			     &setdebugriscvcmdlist, &showdebugriscvcmdlist);
}
