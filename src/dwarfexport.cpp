#include <cstdio>
#include <cstdlib>
#include <frame.hpp>
#include <fstream>
#include <ida.hpp>
#include <idp.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <string>
#include <struct.hpp>
#include <range.hpp>
#include <segment.hpp>

#include "dwarfexport.h"

static bool has_decompiler = false;
std::ofstream logger;

// A mapping of IDA types to dwarf types
using type_record_t = std::map<tinfo_t, Dwarf_P_Die>;

// Sorted list of address -> line info, where the same address may be mapped to different lines
struct line_info
{
    line_info(int nr, bool statement, bool mode16) {
        this->nr = nr;
        this->statement = statement;
        this->mode16 = mode16;
    }
    int nr;
    bool statement;
    bool mode16;
};

using line_info_t = std::multimap<ea_t, line_info>;

/**
 * Add a dwarf type definitions to the compilation unit 'cu' representing
 * the IDA type 'type'. This is implemented for structs, const types,
 * arrays, and pointer types using the following 'add_*_type' functions.
 *
 * @returns The dwarf DIE associated with the new type (or the existing one)
 */
static Dwarf_P_Die get_or_add_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record);

static Dwarf_P_Die add_struct_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record) {
  if (!type.is_struct()) {
    dwarfexport_error("add_struct_type: type is not struct");
  }

  dwarfexport_log("Adding structure type");

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_structure_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  // Add type name
  qstring name;
  if (type.get_type_name(&name)) {
    if (dwarf_add_AT_name(die, (char*) name.c_str(), &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }
    dwarfexport_log("  Name = ", name.c_str());
  }

  // Add type size
  auto size = type.get_size();
  if (size != BADSIZE) {
    if (dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, size, &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_unsigned_const failed: ", dwarf_errmsg(err));
    }
    dwarfexport_log("  Size = ", size);
  }

  auto member_count = type.get_udt_nmembers();
  if (member_count == -1) {
    dwarfexport_error("add_struct_type: get_udt_nmembers error");
  }

  dwarfexport_log("  Member Count = ", member_count);

  for (int i = 0; i < member_count; ++i) {
    udt_member_t member;
    member.offset = i;
    type.find_udt_member(&member, STRMEM_INDEX);
    auto member_type = member.type;
    auto member_die =
        dwarf_new_die(dbg, DW_TAG_member, die, NULL, NULL, NULL, &err);

    // Add member type
    auto member_type_die = get_or_add_type(dbg, cu, member_type, record);
    if (dwarf_add_AT_reference(dbg, member_die, DW_AT_type, member_type_die,
                               &err) == nullptr) {
      dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
    }

    // Add member name
    auto member_name = member.name;
    if (dwarf_add_AT_name(member_die, &member_name[0], &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }

    dwarfexport_log("  Adding Member: ", &member_name[0]);

    // Add member location in struct
    Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
    if (dwarf_add_expr_gen(loc_expr, DW_OP_plus_uconst, member.offset / 8, 0,
                           &err) == DW_DLV_NOCOUNT) {
      dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
    }

    if (dwarf_add_AT_location_expr(dbg, member_die, DW_AT_data_member_location,
                                   loc_expr, &err) == nullptr) {
      dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                        dwarf_errmsg(err));
    }
  }
  return die;
}

static Dwarf_P_Die add_array_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                  const tinfo_t &type, type_record_t &record) {
  if (!type.is_array()) {
    dwarfexport_error("add_array_type: type is not array");
  }

  dwarfexport_log("Adding array type");

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_array_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  auto element_type = type;
  element_type.remove_ptr_or_array();
  auto element_die = get_or_add_type(dbg, cu, element_type, record);

  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, element_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }

  auto elems = type.get_array_nelems();
  if (elems > 0) {
    elems -= 1;

    dwarfexport_log("  Number of elements = ", elems);

    auto subrange =
        dwarf_new_die(dbg, DW_TAG_subrange_type, die, NULL, NULL, NULL, &err);
    if (dwarf_add_AT_unsigned_const(dbg, subrange, DW_AT_upper_bound, elems,
                                    &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                        dwarf_errmsg(err));
    }

    tinfo_t size_type;
    qstring name;

    // Try to get size_t and use it for the index type
    if (parse_decl(&size_type, &name, NULL, "size_t x;", PT_SIL)) {
      auto index_die = get_or_add_type(dbg, cu, size_type, record);
      if (dwarf_add_AT_reference(dbg, subrange, DW_AT_type, index_die,
                                 &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_reference failed: ",
                          dwarf_errmsg(err));
      }
    }
  }
  return die;
}

static Dwarf_P_Die add_const_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                  const tinfo_t &type, type_record_t &record) {
  if (!type.is_const()) {
    dwarfexport_error("add_const_type: type is not const");
  }

  dwarfexport_log("Adding const type");

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_const_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  auto without_const = type;
  without_const.clr_const();
  auto child_die = get_or_add_type(dbg, cu, without_const, record);

  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }
  return die;
}

static Dwarf_P_Die add_ptr_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                const tinfo_t &type, type_record_t &record) {
  if (!type.is_ptr()) {
    dwarfexport_error("add_ptr_type: type is not a pointer");
  }

  dwarfexport_log("Adding pointer type");

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_pointer_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  auto without_ptr = type;
  without_ptr.remove_ptr_or_array();
  auto child_die = get_or_add_type(dbg, cu, without_ptr, record);

  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }
  if (dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, sizeof(ea_t),
                                  &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                      dwarf_errmsg(err));
  }
  return die;
}

static Dwarf_P_Die add_unspecified_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                        const tinfo_t &type, type_record_t &record) {
  dwarfexport_log("Adding unspecified type");

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_unspecified_type, cu, NULL, NULL, NULL, &err);
  if (die == NULL) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  // Add type name
  const char *name = type.dstr();
  if (name && name[0]) {
    if (dwarf_add_AT_name(die, (char*) name, &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }
    dwarfexport_log("  Name = ", name);
  }

  record[type] = die;
  return die;
}

static Dwarf_P_Die add_base_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu, const tinfo_t &type,
                                 type_record_t &record) {
  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  // Add types with unknown- or zero size as unspecified
  std::size_t size = type.get_size();
  if (size == BADSIZE || !size) {
    return add_unspecified_type(dbg, cu, type, record);
  }

  // Decide encoding (note: order is important below, specific checks first, since types can overlap)
  Dwarf_Unsigned enc;
  if (type.is_char()) {
    enc = DW_ATE_signed_char;
  } else if (type.is_uchar()) {
    enc = DW_ATE_unsigned_char;
  } else if (type.is_bool()) {
    enc = DW_ATE_boolean;
  } else if (type.is_int()) {
    enc = type.is_signed() ? DW_ATE_signed : DW_ATE_unsigned;
  } else if (type.is_float() || type.is_double()) {
    enc = DW_ATE_float;
  } else if (type.is_partial()) {
    // Partial types are void types with known size, treat as unsigned char/integer
    if (size == 1) {
      enc = DW_ATE_unsigned_char;
    } else if (size == 2 || size == 4 || size == 8) {
      enc = DW_ATE_unsigned;
    } else {
      return add_unspecified_type(dbg, cu, type, record);        
    }
  } else {
    // Unsupported type added as unspecified for now
    return add_unspecified_type(dbg, cu, type, record);
  }

  // Create base type entry
  die = dwarf_new_die(dbg, DW_TAG_base_type, cu, NULL, NULL, NULL, &err);
  if (die == NULL) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  // Add type name
  const char *name = type.dstr();
  if (name && name[0]) {
    if (dwarf_add_AT_name(die, (char*) name, &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }
    dwarfexport_log("  Name = ", name);
  }

  // Add type size
  if (dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, size, &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ", dwarf_errmsg(err));
  }
  dwarfexport_log("  Size = ", size);

  // Add encoding
  if (dwarf_add_AT_unsigned_const(dbg, die, DW_AT_encoding, enc, &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ", dwarf_errmsg(err));
  }
  dwarfexport_log("  Encoding = ", enc);

  record[type] = die;
  return die;
}

static Dwarf_P_Die get_or_add_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record) {
  if (record.find(type) != record.end()) {
    return record[type];
  }

  dwarfexport_log("Adding new type");

  if (type.is_void() || type.is_unknown() || !type.is_correct()) {
    return add_unspecified_type(dbg, cu, type, record);
  } else if (type.is_const()) {
    return add_const_type(dbg, cu, type, record);
  } else if (type.is_ptr()) {
    return add_ptr_type(dbg, cu, type, record);
  } else if (type.is_array()) {
    return add_array_type(dbg, cu, type, record);
  } else if (type.is_struct()) {
    return add_struct_type(dbg, cu, type, record);
  } else if (type.is_union()) {
    // Unions not yet supported
    return add_unspecified_type(dbg, cu, type, record);
  } else {
    return add_base_type(dbg, cu, type, record);
  }
}

/**
 * For a given IDA decompiler variable 'var' from a given function
 * 'cfunc', add a dwarf variable to the provided function DIE 'func_die'.
 *
 * * @returns The dwarf DIE associated with the new variable
 */
static Dwarf_P_Die add_variable(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                Dwarf_P_Die func_die, cfuncptr_t cfunc,
                                const lvar_t &var, type_record_t &record) {
  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_variable, func_die, NULL, NULL, NULL, &err);

  // Add var type. We could check for 'typed' here, but this is sometimes
  // returns strange values (bug?), and I think lvars in the decompiled view
  // must be types, so skip the check.
  auto var_type = var.type();
  auto var_type_die = get_or_add_type(dbg, cu, var_type, record);
  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }

  auto name = var.name;
  if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  dwarfexport_log("Adding local variable: ", &name[0]);

  if (var.is_stk_var()) {
    auto loc_expr = decompiler_stack_lvar_location(dbg, cfunc, var);
    if (loc_expr) {
      if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr,
                                     &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                          dwarf_errmsg(err));
      }
    }
  } else if (var.location.is_reg1()) {
    // Try to get the DWARF register number from the IDA register number.
    // For whatever reason, the mapping is different for registers when
    // passing arguments, so we don't do those.
    auto reg_num = translate_register_num(var.location.reg1());

    if (reg_num != -1) {
      dwarfexport_log("Translated IDA register #", var.location.reg1(), " to #",
                      reg_num);

      Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
      if (dwarf_add_expr_gen(loc_expr, DW_OP_regx, reg_num, 0, &err) ==
          DW_DLV_NOCOUNT) {
        dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
      }
      if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr,
                                     &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                          dwarf_errmsg(err));
      }
    } else {
      dwarfexport_log("Unable to translate register #", var.location.reg1());
    }
  }

  return die;
}

/**
 * Adds a DWARF variable to the provided function 'func_die' for each
 * variable in the IDA disassembly view.
 */
static void add_disassembler_func_info(std::shared_ptr<DwarfGenInfo> info,
                                       Dwarf_P_Die func_die, Dwarf_P_Die cu,
                                       func_t *func, type_record_t &record) {
  auto dbg = info->dbg;
  Dwarf_Error err = 0;

  auto frame = get_frame(func);
  if (frame == nullptr) {
    return;
  }

  for (std::size_t i = 0; i < frame->memqty; ++i) {
    auto name = get_member_name(frame->members[i].id);

    // Ignore these special 'variables'
    if (name == " s" || name == " r") {
      continue;
    }

    dwarfexport_log("Adding local variable: ", &name[0]);

    Dwarf_P_Die die;
    die = dwarf_new_die(dbg, DW_TAG_variable, func_die, NULL, NULL, NULL, &err);

    if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }

    auto loc_expr =
        disassembler_stack_lvar_location(dbg, func, &frame->members[i]);

    if (loc_expr == nullptr) {
      continue;
    }

    auto member_struct = get_sptr(&frame->members[i]);
    if (member_struct) {
      tinfo_t type;
      if (type.get_numbered_type(nullptr, member_struct->ordinal)) {
        auto var_type_die = get_or_add_type(dbg, cu, type, record);
        if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
            nullptr) {
          dwarfexport_error("dwarf_add_AT_reference failed: ",
                            dwarf_errmsg(err));
        }
      }
    }

    if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                        dwarf_errmsg(err));
    }
  }
}

/**
 * Adds a DWARF variable to the provided function 'func_die' for each
 * variable in the IDA decompiler view.
 *
 * @param info A handle returned by a previous call to 'generate_dwarf_object'
 * @param cu   The dwarf compilation unit containing the function
 * @param func_die The dwarf function to add variables and line info for
 * @param func The IDA function handle for this function
 * @param file An output file stream used for storing the decompiled source
 * @param linecount The current number of lines in 'file'
 * @param file_index The dwarf file index associated with 'cu'
 * @param symbol_index The symbol index associated with the function (unused)
 * @param record The type record to update when adding variable types
 */
static void add_decompiler_func_info(std::shared_ptr<DwarfGenInfo> info,
                                     Dwarf_P_Die cu, Dwarf_P_Die func_die,
                                     func_t *func, std::ostream &file,
                                     int &linecount, Dwarf_Unsigned file_index,
                                     Dwarf_Unsigned symbol_index,
                                     type_record_t &record,
                                     line_info_t &lines,
                                     ea_t previous_line_addr) {
  auto dbg = info->dbg;
  auto err = info->err;

  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT | DECOMP_NO_XREFS);

  if (cfunc == nullptr) {
    dwarfexport_log("Failed to decompile function at ", func->start_ea);
    return;
  }

  // Add lvars (from decompiler)
  auto &lvars = *cfunc->get_lvars();
  for (std::size_t i = 0; i < lvars.size(); ++i) {
    if (lvars[i].name.size()) {
      add_variable(dbg, cu, func_die, cfunc, lvars[i], record);
    }
  }

  // Add line info
  const auto &sv = cfunc->get_pseudocode();
  const auto &bounds = cfunc->get_boundaries();
  const auto &eamap = cfunc->get_eamap();
  for (std::size_t i = 0; i < sv.size(); ++i, ++linecount) {
    qstring buf;
    qstring line = sv[i].line;
    tag_remove(&buf, line);

    auto stripped_buf = std::string(buf.c_str());
    file << stripped_buf + "\n";

    dwarfexport_log("Processing line: ", stripped_buf);

    ctree_item_t item;
    std::size_t index = stripped_buf.find_first_not_of(' ');
    if (index == std::string::npos) {
      continue;
    }

    // Each column in the line can map to different addresses. We keep things simple and map the
    // line to the first valid column address.
    ea_t line_addr = 0;
    for (; index < stripped_buf.size() && !line_addr; ++index) {
        if (!cfunc->get_line_item(line.c_str(), index, true, nullptr, &item, nullptr)) {
        continue;
      }

      if (item.citype != VDI_EXPR) {
        continue;
      }

      // item.get_ea returns strange values, so use the item_t ea for exprs for now.
      ea_t addr = item.it->ea;

      // Select the first valid address, ignoring strange addresses outside of this function.
      if (addr != (ea_t)-1 && addr >= func->start_ea && addr <= func->end_ea) {
        line_addr = addr;
      }
    }

    // Add line if its address was found and if it does not map to the same address as the
    // previous line. Assume all lines are DWARF statements until we have found a simple way to
    // differentiate between statements and multi-line expressions.
    if (line_addr && line_addr != previous_line_addr) {
      dwarfexport_log("Mapping line #", linecount, " to address 0x", hex(line_addr));
      lines.insert({line_addr, line_info(linecount, true, get_processor_mode16(line_addr))});
      previous_line_addr = line_addr;
    }
  }

  // Add a little space between the functions
  file << "\n\n";
  linecount += 2;
}

static Dwarf_P_Die add_function(std::shared_ptr<DwarfGenInfo> info,
                                Options &options, Dwarf_P_Die cu, func_t *func,
                                std::ostream &file, int &linecount,
                                Dwarf_Unsigned file_index,
                                type_record_t &record, line_info_t &lines) {
  auto dbg = info->dbg;
  auto err = info->err;
  Dwarf_P_Die die;
  die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, nullptr, nullptr, nullptr,
                      &err);
  if (die == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  // Add frame base
  // TODO: what to do for non-bp based frames
  Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
  if (dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0, &err) ==
      DW_DLV_NOCOUNT) {
    dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
  }
  if (dwarf_add_AT_location_expr(dbg, die, DW_AT_frame_base, loc_expr, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_location_expr failed: ", dwarf_errmsg(err));
  }

  // Add function name
  auto name = get_long_name(func->start_ea);
  char *c_name = &*name.begin();

  if (dwarf_add_AT_name(die, c_name, &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  auto mangled_name = get_name(func->start_ea);
  if (dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, &mangled_name[0],
                          &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_string failed: ", dwarf_errmsg(err));
  }

  dwarfexport_log("Adding function ", &name[0], " (", &mangled_name[0], ")");

  // Add ret type
  tinfo_t func_type_info;
  if (get_tinfo(&func_type_info, func->start_ea)) {
    auto rettype = func_type_info.get_rettype();
    auto rettype_die = get_or_add_type(dbg, cu, rettype, record);
    if (dwarf_add_AT_reference(dbg, die, DW_AT_type, rettype_die, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
    }
  }

  // Add function bounds
  dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, func->start_ea, 0, &err);
  dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, func->end_ea - 1, 0, &err);

  auto is_named = has_name(get_flags(func->start_ea));
  if (has_decompiler && options.use_decompiler() &&
      (!options.only_decompile_named_funcs() ||
       (options.only_decompile_named_funcs() && is_named))) {

    // Add location declaration
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index, &err);
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, linecount, &err);

    // The start of every function should have a line entry
    lines.insert({func->start_ea, line_info(linecount, true, get_processor_mode16(func->start_ea))});

    add_decompiler_func_info(info, cu, die, func, file, linecount, file_index,
                             0, record, lines, func->start_ea);
  } else {
    add_disassembler_func_info(info, cu, die, func, record);
  }

  return die;
}

/**
 * Add all structures to the debug output. This is useful for allowing casts
 * to types in the debugger that may not have actually been used at the time
 * the debug info was being exported.
 */
void add_structures(Dwarf_P_Debug dbg, Dwarf_P_Die cu, type_record_t &record) {
  dwarfexport_log("Adding unused types");
  for (auto idx = get_first_struc_idx(); idx != BADADDR;
       idx = get_next_struc_idx(idx)) {
    auto tid = get_struc_by_idx(idx);
    auto struc = get_struc(tid);
    tinfo_t type;

    if (type.get_numbered_type(nullptr, struc->ordinal)) {
      get_or_add_type(dbg, cu, type, record);
    }
  }
}

/**
 * Add dwarf info for the global variables in this file. These entries are
 * not given a textual representation, only a location and type.
 */
void add_global_variables(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                          type_record_t &record) {
  dwarfexport_log("Adding global variables");
  Dwarf_Error err = 0;
  auto seg_count = get_segm_qty();

  for (auto i = 0; i < seg_count; ++i) {
    auto seg = getnseg(i);
    if (seg->type != SEG_DATA && seg->type != SEG_BSS) {
      continue;
    }

    for (auto addr = seg->start_ea; addr < seg->end_ea; ++addr) {
      qstring name;
      if (!get_name(&name, addr) || name.empty()) {
        continue;
      }

      // When no type information has been set, we may still try to guess the type.
      tinfo_t type;
      if (!get_tinfo(&type, addr)) {
        if (guess_tinfo(&type, addr) != GUESS_FUNC_OK) {
          continue;
        }
      }

      dwarfexport_log("Adding global variable");
      std::string lname(name.c_str());
      dwarfexport_log("  name = ", lname);

      dwarfexport_log("  location = 0x", hex(addr));

      auto die =
          dwarf_new_die(dbg, DW_TAG_variable, cu, NULL, NULL, NULL, &err);
      auto var_type_die = get_or_add_type(dbg, cu, type, record);

      if (dwarf_add_AT_name(die, const_cast<char*>(name.c_str()), &err) == NULL) {
        dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
      }

      if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
          nullptr) {
        dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
      }

      // FIXME: this won't work in shared libs
      Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
      if (dwarf_add_expr_addr_b(loc_expr, addr, 0, &err) == DW_DLV_NOCOUNT) {
        dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
      }
      if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr,
                                     &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                          dwarf_errmsg(err));
      }
    }
  }
}

static Dwarf_Unsigned get_line_isa(std::shared_ptr<DwarfGenInfo> info, const line_info &line)
{
    // ISA only relevant for ARM32 where we need to select between ARM and THUMB instructions
    if (info->proc != Proc::ARM || info->mode != Mode::BIT32)
      return DW_ISA_UNKNOWN;

    return (line.mode16 ? DW_ISA_ARM_thumb : DW_ISA_ARM_arm);
}

static void add_debug_info(std::shared_ptr<DwarfGenInfo> info,
                          std::ostream &sourcefile, Options &options,
                          mode16_addrs_t &mode16_addrs) {
  auto dbg = info->dbg;
  auto err = info->err;
  Dwarf_P_Die cu;
  cu = dwarf_new_die(dbg, DW_TAG_compile_unit, nullptr, nullptr, nullptr,
                     nullptr, &err);
  if (cu == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  Dwarf_Unsigned file_index = 0;
  if (options.use_decompiler()) {
    if (dwarf_add_AT_name(cu, (char*) options.c_filename().c_str(), &err) == nullptr) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }

    auto dir_index =
        dwarf_add_directory_decl(dbg, options.outdir, &err);
    file_index = dwarf_add_file_decl(dbg, (char*) options.c_filename().c_str(), dir_index,
                                     0, 0, &err);

    dwarf_add_AT_comp_dir(cu, options.outdir, &err);
  }

  int linecount = 1;
  int progress = 0;
  type_record_t record;
  line_info_t lines;
  auto seg_qty = get_segm_qty();
  ea_t highest_ea = 0;
  for (std::size_t segn = 0; segn < seg_qty; ++segn) {
    auto seg = getnseg(segn);
    if (seg == nullptr) {
      dwarfexport_error("Unable to getnseg() segment number ", segn);
    }

    // Only consider EXEC segments
    // TODO: Skip plt/got?
    if (!(seg->perm & SEGPERM_EXEC) && seg->type != SEG_CODE) {
      dwarfexport_log("Segment #", segn, " is not executable. Skipping.");
      continue;
    }

    qstring segname;
    get_segm_name(&segname, seg);
    std::string lsegname(segname.c_str());
    dwarfexport_log("Adding functions from: ", lsegname);

    func_t *f = get_func(seg->start_ea);
    if (f == nullptr || f->start_ea != seg->start_ea) {
      // In some cases, the start of the section may not actually be a function,
      // or it may be a function chunk (in which case `get_func` returns the
      // parent function start), so get the first available actual function.
      f = get_next_func(seg->start_ea);

      if (f == nullptr) {
        dwarfexport_log("Skipping ", lsegname, " because it has no functions");
        continue;
      }
    }

    for (; f != nullptr; f = get_next_func(f->start_ea)) {
      if (f->start_ea >= seg->end_ea) {
        break;
      }

      add_function(info, options, cu, f, sourcefile, linecount, file_index, record, lines);
      highest_ea = qmax(highest_ea, f->end_ea);
      
      if (linecount > progress) {
        progress += 1000;
        if (user_cancelled()) {
            return;
        }
        replace_wait_box("Running DWARF export... Line %d\n", linecount);
      }
    }
  }

  // Insert line number info, in address order. (Must be done separately since libdwarf does not
  // sort for us). Also create a list of mode16 address ranges (kept empty when not relevant).
  if (lines.size()) {
    ea_t mode16_start = BADADDR;
    for (const auto &line: lines) {
      ea_t addr = line.first;
      const line_info &linfo = line.second;
      Dwarf_Unsigned isa = get_line_isa(info, linfo);
      if (dwarf_add_line_entry_c(dbg, file_index, addr, linfo.nr, 0, linfo.statement, 0, 0, 0,
                                 isa, 0, &err) != DW_DLV_OK) {
        dwarfexport_error("dwarf_add_line_entry failed: ", dwarf_errmsg(err));
      }
      if (mode16_start == BADADDR && isa == DW_ISA_ARM_thumb) {
        mode16_start = addr;
      } else if (mode16_start != BADADDR && isa != DW_ISA_ARM_thumb) {
        mode16_addrs.emplace_back(mode16_start, addr);
        mode16_start = BADADDR;
      }
    }

    if (dwarf_lne_end_sequence(dbg, highest_ea, &err) != DW_DLV_OK) {
        dwarfexport_error("dwarf_lne_end_sequence failed: ", dwarf_errmsg(err));
    }
  }

  if (dwarf_add_die_to_debug(dbg, cu, &err) != DW_DLV_OK) {
    dwarfexport_error("dwarf_add_die_to_debug failed: ", dwarf_errmsg(err));
  }

  // Add the global variables (but don't add a file location)
  add_global_variables(dbg, cu, record);

  // Add any other structures
  add_structures(dbg, cu, record);
}

plugmod_t * idaapi init(void) {
  if (init_hexrays_plugin()) {
    msg("dwarfexport: Using decompiler\n");
    has_decompiler = true;
  } else {
    msg("dwarfexport: No decompiler found\n");
  }
  return PLUGIN_OK;
}

bool idaapi run(size_t) {
  bool wait_box_shown = false;
  bool ret = true;
  try {
    auto default_options =
        (has_decompiler) ? Options::ATTACH_DEBUG_INFO | Options::USE_DECOMPILER
                         : Options::ATTACH_DEBUG_INFO;
    Options options(default_options);

    qgetcwd(options.outdir, QMAXPATH);
    get_root_filename(options.filename, QMAXPATH);

    const char *dialog = "STARTITEM 0\n"
                         "Dwarf Export\n\n"
                         "Select the location to save the exported data:\n"
                         "<Save:F:1:::>\n"
                         "Export Options\n <Use Decompiler:C>\n"
                         "<Only Decompile Named Functions:C>\n"
                         "<Attach Debug Info:C>\n"
                         "<Permissive ELF Layout:C>\n"
                         "<Verbose:C>>\n";

    if (ask_form(dialog, options.outdir, &options.export_options) ==
        1) {

      size_t dirlen = strlen(options.outdir);
      if (dirlen && options.outdir[dirlen-1] == PATH_SEP) {
        options.outdir[dirlen-1] = '\0';
      }

      if (options.verbose()) {
        logger = std::ofstream("dwarfexport.log");
        msg("Verbose mode enabled. Logging to dwarfexport.log\n");
      }

      if (!options.attach_debug_info()) {
        dwarfexport_log("Generating detached debug info");
      }
      if (options.only_decompile_named_funcs()) {
        dwarfexport_log("Only decompiling named functions");
      }

      std::ofstream sourcefile;
      if (options.use_decompiler()) {
        dwarfexport_log("Using decompiler with exported source file path: ",
                        options.c_filepath());
        sourcefile = std::ofstream(options.c_filepath());
      }

      show_wait_box("Running DWARF export...\n");
      wait_box_shown = true;

      dwarfexport_log("Setting up DWARF object");
      auto info = generate_dwarf_object(options);

      mode16_addrs_t mode16_addrs;
      dwarfexport_log("Adding DWARF debug information");
      add_debug_info(info, sourcefile, options, mode16_addrs);

      dwarfexport_log("Writing out DWARF file to disk");
      write_dwarf_file(info, options, mode16_addrs);

      dwarfexport_log("All done");
      msg("dwarfexport: Done\n");
    }
  } catch (const std::exception &e) {
    std::string msg = "A dwarfexport error occurred: " + std::string(e.what());
    warning(msg.c_str());
    ret = false;
  } catch (...) {
    warning("A dwarfexport error occurred");
    ret = false;
  }
  
  if (wait_box_shown)
    hide_wait_box();
    
  return ret;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,                // plugin flags
    init,                      // initialize
    nullptr,                   // terminate. this pointer may be nullptr.
    run,                       // invoke plugin
    nullptr,                   // long comment about the plugin
    nullptr,                   // multiline help about the plugin
    "Export Dwarf Debug Info", // the preferred short name of the plugin
    nullptr                    // the preferred hotkey to run the plugin
};
