#include "import.h"

#include "../../utils/logger/logger.h"
#include "../../utils/utils.h"

#include <cstdint>
#include <string>

#include <bytes.hpp>
#include <dbg.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>

namespace omd {
    import_entry::import_entry(const nlohmann::json& j) {
        if (j.contains("name")) {
            data_.name = j["name"].get<std::string>().c_str();
        }

        if (j.contains("declaration")) {
            data_.declaration = j["declaration"].get<std::string>().c_str();
        }

        if (j.contains("comment")) {
            data_.comment = j["comment"].get<std::string>().c_str();
        }

        if (j.contains("color")) {
            data_.color = j["color"].get<std::uint32_t>();
        }

        if (j.contains("operations")) {
            if (const auto& ops = j["operations"]; ops.is_array() && !ops.empty()) {
                for (const auto& op : ops) {
                    transfer_data::ea_op_data operation{};

                    if (op.contains("offset")) {
                        operation.type = ea_calc;
                        operation.offset = op["offset"].get<std::int64_t>();
                    } else if (op.contains("insn_format")) {
                        if (const auto& layout = op["insn_format"];
                            layout.is_array() && layout.size() == max_insn_layout_array_size) {
                            operation.type = addr_calc;
                            operation.opcode_length = layout[opcode_length].get<std::uint32_t>();
                            operation.displ_length = layout[displ_length].get<std::uint32_t>();
                        }
                    }

                    data_.ea_ops_chain.push_back(operation);
                }
            }
        }

        if (j.contains("breakpoint")) {
            if (const auto& bpt = j["breakpoint"]; bpt.is_array() && bpt.size() == max_bpt_array_size) {
                data_.breakpoint.exists = bpt[breakpoint_exists].get<bool>();
                data_.breakpoint.type = bpt[breakpoint_type].get<bpttype_t>();
                data_.breakpoint.size = bpt[breakpoint_size].get<asize_t>();
            }
        }
    }

    void import_entry::apply(ea_t address, const transfer_options& options) const {
        bool success = true;

        if (!adjust_address(address)) {
            logging::error("Failed to adjust address: 0x{:X}, {}\n", address, get_display_name());
            return;
        }

        if (options.names && !set_name(address)) {
            logging::error("Failed to set name: {} (0x{:X})\n", data_.name.c_str(), address);
            success = false;
        }

        if (options.declarations) {
            if (auto const result = set_declaration(address); result != decl_result::success) {
                switch (result) {
                case decl_result::no_type_info:
                    logging::error(
                        "Failed to set declaration, address doesn't support type info: {} (0x{:X})\n",
                        data_.declaration.c_str(),
                        address
                    );
                    break;
                case decl_result::parse_failed:
                    logging::error("Failed to parse declaration: {} (0x{:X})\n", data_.declaration.c_str(), address);
                    break;
                case decl_result::set_tinfo_failed:
                    logging::error("Failed to set declaration: {} (0x{:X})\n", data_.declaration.c_str(), address);
                    break;
                default:
                    break;
                }
                success = false;
            }
        }

        if (options.comments) {
            if (auto const result = set_comment(address); result != cmt_result::success) {
                logging::error(
                    "Failed to set {}: {} (0x{:X})\n",
                    (result == cmt_result::func_cmt_failed) ? "function comment" : "comment",
                    data_.comment.c_str(),
                    address
                );
                success = false;
            }
        }

        if (options.breakpoints && !set_breakpoint(address)) {
            logging::error("Failed to add breakpoint at 0x{:X}\n", address);
            success = false;
        }

        if (options.colors) {
            set_color(address);
        }

        if (success) {
            logging::debug("Success: 0x{:X}, {}\n", address, get_display_name());
        } else {
            logging::debug("Completed with errors: 0x{:X}, {}\n", address, get_display_name());
        }
    }

    const transfer_data& import_entry::get_data() const {
        return data_;
    }

    const char* import_entry::get_display_name() const {
        for (const auto* str : {&data_.name, &data_.declaration, &data_.comment}) {
            if (!str->empty()) {
                return str->c_str();
            }
        }
        return "None";
    }

    bool import_entry::adjust_address(ea_t& address) const {
        for (const auto& op : data_.ea_ops_chain) {
            if (op.type == ea_calc) {
                address += op.offset;
                if (!is_loaded(address)) {
                    return false;
                }
            } else if (op.type == addr_calc) {
                if (auto const data = address + op.opcode_length; is_loaded(data)) {
                    if (inf_is_64bit()) {
                        auto const rel_offset = static_cast<std::int32_t>(get_dword(address + op.opcode_length));
                        auto const next_insn = address + op.opcode_length + op.displ_length;
                        address = next_insn + rel_offset;
                    } else {
                        address = get_dword(address + op.opcode_length);
                    }
                } else {
                    return false;
                }
            }
        }
        return is_loaded(address);
    }

    bool import_entry::set_name(ea_t const address) const {
        if (data_.name.empty()) {
            return true;
        }

        if (!::set_name(address, data_.name.c_str(), SN_NOCHECK)) {
            return false;
        }

        return true;
    }

    import_entry::decl_result import_entry::set_declaration(ea_t const address) const {
        if (data_.declaration.empty()) {
            return decl_result::success;
        }

        if (!utils::has_type_info(address)) {
            return decl_result::no_type_info;
        }

        tinfo_t tif{};
        qstring name{};
        if (parse_decl(&tif, &name, nullptr, data_.declaration.c_str(), PT_TYP | PT_VAR | PT_SIL) && tif.is_correct()) {
            if (!set_tinfo(address, &tif)) {
                return decl_result::set_tinfo_failed;
            }
        } else {
            return decl_result::parse_failed;
        }

        return decl_result::success;
    }

    import_entry::cmt_result import_entry::set_comment(ea_t const address) const {
        if (data_.comment.empty()) {
            return cmt_result::success;
        }

        if (auto const func = get_func(address); func != nullptr && func->start_ea == address) {
            if (!set_func_cmt(func, data_.comment.c_str(), true)) {
                return cmt_result::func_cmt_failed;
            }
        }

        else {
            if (!set_cmt(address, data_.comment.c_str(), true)) {
                return cmt_result::cmt_failed;
            }
        }

        return cmt_result::success;
    }

    bool import_entry::set_breakpoint(ea_t const address) const {
        if (!data_.breakpoint.exists || exist_bpt(address)) {
            return true;
        }

        return add_bpt(
            address, data_.breakpoint.size, data_.breakpoint.type == 0 ? BPT_DEFAULT : data_.breakpoint.type
        );
    }

    void import_entry::set_color(ea_t const address) const {
        if (data_.color != 0) {
            auto const bgr = ((data_.color & 0xFF) << 16) | (data_.color & 0xFF00) | ((data_.color >> 16) & 0xFF);
            set_item_color(address, bgr);
        }
    }
} // namespace omd

namespace omd::importer {
    import_result apply_transfer(
        const nlohmann::json& transfer, const transfer_options& options, const address_region& range
    ) {
        import_result result{};
        pattern_search const scanner{range.start, range.end};

        for (const auto& object : transfer) {
            if (user_cancelled()) {
                result.status = operation_status::cancelled;
                return result;
            }

            if (!object.contains("signature")) {
                continue;
            }

            import_entry const entry{object};

            ++result.total;
            auto const signature = object["signature"].get<std::string>();
            auto const address = scanner.search(signature.c_str(), [entry, options](const ea_t address) {
                entry.apply(address, options);
            });

            if (address == BADADDR) {
                logging::debug("Pattern not found: {}\n", signature.c_str());
            } else {
                ++result.found;
            }
        }

        return result;
    }
} // namespace omd::importer
