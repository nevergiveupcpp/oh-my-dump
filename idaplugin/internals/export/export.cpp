#include "export.h"
#include "export_filters.h"

#include "../patterns/byte_pattern.h"
#include "../../utils/logger/logger.h"
#include "utils/utils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

#include <bytes.hpp>
#include <dbg.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

namespace {
    [[nodiscard]] bool is_function_start(const ea_t address) {
        auto const func = get_func(address);
        return func != nullptr && func->start_ea == address;
    }

    [[nodiscard]] bool matches_rule(const qstring& value, const omd::export_filters::rule& rule) {
        switch (rule.match) {
        case omd::export_filters::match::exact:
            return value == rule.pattern.data();
        case omd::export_filters::match::prefix:
            return value.starts_with(rule.pattern.data());
        default:
            return false;
        }
    }

    template<std::size_t Count> [[nodiscard]] bool is_auto_generated(
        const qstring& value, const std::array<omd::export_filters::rule, Count>& rules
    ) {
        for (const auto& rule : rules) {
            if (matches_rule(value, rule)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::uint32_t ida_color_to_json(const bgcolor_t color) {
        return ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF);
    }

    [[nodiscard]] bool contains_address(const omd::address_region& range, const ea_t address) {
        return range.valid() && address >= range.start && address < range.end;
    }

    [[nodiscard]] bool is_code_item(const ea_t address) {
        auto const head = get_item_head(address);
        return head != BADADDR && is_code(get_flags(head));
    }

    [[nodiscard]] bool create_rip_operation(
        omd::transfer_data::ea_op_data* operation, const insn_t& insn, const ea_t target
    ) {
        for (std::uint32_t i{}; i < UA_MAXOP; ++i) {
            op_t const* op = &insn.ops[i];
            if (op->type == o_void) {
                break;
            }

            if (op->offb <= 0) {
                continue;
            }

            auto const offset = static_cast<std::uint32_t>(op->offb);
            if (offset + sizeof(std::uint32_t) > insn.size) {
                continue;
            }

            auto const encoded_target = static_cast<std::int32_t>(get_dword(insn.ea + offset));

            if (inf_is_64bit()) {
                auto const rel = encoded_target;
                auto const resolved = static_cast<std::int64_t>(insn.ea) + static_cast<std::int64_t>(insn.size) +
                                      static_cast<std::int64_t>(rel);
                if (resolved < 0 || static_cast<ea_t>(resolved) != target) {
                    continue;
                }
            } else {
                auto const abs = encoded_target;
                if ((abs < inf_get_min_ea() || abs >= inf_get_max_ea()) || abs != target) {
                    continue;
                }
            }

            operation->type = omd::addr_calc;
            operation->opcode_length = offset;
            operation->displ_length = static_cast<std::uint32_t>(insn.size) - offset;
            return true;
        }

        return false;
    }

    void add_address(std::vector<ea_t>& addresses, const omd::address_region& range, const ea_t address) {
        if (address == BADADDR || !contains_address(range, address)) {
            return;
        }

        addresses.push_back(address);
    }

    [[nodiscard]] bool get_signed_name(qstring* name, const ea_t address, const omd::export_filter& filter) {
        qstring visible_name{};
        if (get_name(&visible_name, address, GN_VISIBLE | GN_NOT_DUMMY) <= 0 ||
            !filter.accept_name(address, visible_name)) {
            return false;
        }

        *name = visible_name;
        return true;
    }

    [[nodiscard]] bool get_function_comment(qstring* comment, func_t const* func, const omd::export_filter& filter) {
        if (func == nullptr) {
            return false;
        }

        qstring candidate{};
        if (get_func_cmt(&candidate, func, true) > 0 && filter.accept_comment(candidate)) {
            *comment = candidate;
            return true;
        }

        candidate.clear();
        if (get_func_cmt(&candidate, func, false) > 0 && filter.accept_comment(candidate)) {
            *comment = candidate;
            return true;
        }

        return false;
    }

    [[nodiscard]] bool get_item_comment(qstring* comment, const ea_t address, const omd::export_filter& filter) {
        qstring candidate{};
        if (get_cmt(&candidate, address, true) > 0 && filter.accept_comment(candidate)) {
            *comment = candidate;
            return true;
        }

        candidate.clear();
        if (get_cmt(&candidate, address, false) > 0 && filter.accept_comment(candidate)) {
            *comment = candidate;
            return true;
        }

        return false;
    }

    [[nodiscard]] omd::operation_status collect_signed_addresses(
        std::vector<ea_t>& addresses, const omd::address_region& range, const omd::export_filter& filter
    ) {
        auto const count = get_nlist_size();
        for (std::size_t index{}; index < count; ++index) {
            if (user_cancelled()) {
                return omd::operation_status::cancelled;
            }

            auto const address = get_nlist_ea(index);

            qstring name{};
            if (get_signed_name(&name, address, filter)) {
                add_address(addresses, range, address);
            }
        }

        return omd::operation_status::completed;
    }

    [[nodiscard]] omd::operation_status collect_comment_addresses(
        std::vector<ea_t>& addresses, const omd::transfer_options& options, const omd::address_region& range
    ) {
        if (!options.comments) {
            return omd::operation_status::completed;
        }

        omd::export_filter const filter{{options.filter_noise}};

        auto const function_count = get_func_qty();
        for (std::size_t index{}; index < function_count; ++index) {
            if (user_cancelled()) {
                return omd::operation_status::cancelled;
            }

            auto const func = getn_func(index);
            qstring comment{};
            if (get_function_comment(&comment, func, filter)) {
                add_address(addresses, range, func->start_ea);
            }
        }

        for (ea_t address = range.start; address != BADADDR && address < range.end;
             address = next_head(address, range.end)) {
            if (user_cancelled()) {
                return omd::operation_status::cancelled;
            }

            qstring comment{};
            if (get_item_comment(&comment, address, filter)) {
                add_address(addresses, range, address);
            }
        }

        return omd::operation_status::completed;
    }

    struct collected_addresses {
        omd::operation_status status{omd::operation_status::completed};
        std::vector<ea_t> addresses{};
    };

    collected_addresses collect_export_addresses(
        const omd::transfer_options& options, const omd::address_region& range
    ) {
        collected_addresses result{};
        omd::export_filter const filter{{options.filter_noise}};

        if (options.names || options.declarations || options.colors || options.breakpoints) {
            result.status = collect_signed_addresses(result.addresses, range, filter);
            if (result.status == omd::operation_status::cancelled) {
                return result;
            }
        }

        result.status = collect_comment_addresses(result.addresses, options, range);
        if (result.status == omd::operation_status::cancelled) {
            return result;
        }

        std::ranges::sort(result.addresses);
        auto const [first, last] = std::ranges::unique(result.addresses);
        result.addresses.erase(first, last);
        return result;
    }
} // namespace

namespace omd {
    bool export_filter::accept_name(const ea_t address, const qstring& name) const {
        if (!options_.enabled) {
            return true;
        }

        if (name.empty()) {
            return false;
        }

        if (auto const flags = get_flags(address); !has_user_name(flags) || has_auto_name(flags)) {
            return false;
        }

        if (is_auto_generated(name, export_filters::name_rules)) {
            return false;
        }

        return !is_function_start(address) || !is_auto_generated(name, export_filters::function_name_rules);
    }

    bool export_filter::accept_declaration(const qstring& declaration) const {
        if (!options_.enabled) {
            return true;
        }

        if (declaration.empty()) {
            return false;
        }

        return !is_auto_generated(declaration, export_filters::declaration_rules);
    }

    bool export_filter::accept_comment(const qstring& comment) const {
        if (!options_.enabled) {
            return true;
        }

        if (comment.empty()) {
            return false;
        }

        return !is_auto_generated(comment, export_filters::comment_rules);
    }

    export_entry::export_entry(const ea_t address, const transfer_options& options, const address_region& range) :
        address_(address),
        range_(range),
        options_(options),
        filter_(filter_options{options.filter_noise}) {
    }

    bool export_entry::collect() {
        collect_name();

        if (options_.declarations || (options_.names && !data_.name.empty() && is_function_start(address_))) {
            collect_declaration();
        }

        if (options_.comments) {
            collect_comment();
        }

        if (options_.colors) {
            collect_color();
        }

        if (options_.breakpoints) {
            collect_breakpoint();
        }

        if (!has_export_data()) {
            logging::debug("Skipped empty export item: 0x{:X}\n", address_);
            return false;
        }

        if (!collect_signature()) {

            if (!data_.name.empty()) {
                logging::info(
                    "Skipped export item, failed to create signature: 0x{:X}: Name: {}\n", address_, data_.name.c_str()
                );
            }

            logging::debug("Skipped export item, failed to create signature: 0x{:X}\n", address_);
            return false;
        }

        logging::debug("Export item: 0x{:X}, {}\n", address_, get_display_name());
        return true;
    }

    nlohmann::ordered_json export_entry::to_json() const {
        auto object = nlohmann::ordered_json::object();
        if (options_.names && !data_.name.empty()) {
            object["name"] = data_.name.c_str();
        }

        if (!data_.declaration.empty()) {
            object["declaration"] = data_.declaration.c_str();
        }

        if (!data_.comment.empty()) {
            object["comment"] = data_.comment.c_str();
        }

        if (data_.color != 0) {
            object["color"] = data_.color;
        }

        if (data_.breakpoint.exists) {
            object["breakpoint"] = {
                data_.breakpoint.exists,
                data_.breakpoint.type,
                data_.breakpoint.size,
            };
        }

        if (!data_.ea_ops_chain.empty()) {
            auto operations = nlohmann::ordered_json::array();
            for (const auto& operation : data_.ea_ops_chain) {
                if (operation.type == ea_calc) {
                    operations.push_back({{"offset", operation.offset}});
                } else if (operation.type == addr_calc) {
                    operations.push_back({
                        {"insn_format",
                         {
                             operation.opcode_length,
                             operation.displ_length,
                         }},
                    });
                }
            }

            if (!operations.empty()) {
                object["operations"] = operations;
            }
        }

        object["signature"] = signature_;

        return object;
    }

    const transfer_data& export_entry::get_data() const {
        return data_;
    }

    const char* export_entry::get_display_name() const {
        for (const auto* str : {&data_.name, &data_.declaration, &data_.comment}) {
            if (!str->empty()) {
                return str->c_str();
            }
        }
        return "None";
    }

    bool export_entry::collect_signature() {
        if (is_code_item(address_)) {
            auto const result = collect_direct_signature();
            if (!result) {
                return collect_xref_signature();
            }
            return result;
        }

        return collect_xref_signature();
    }

    bool export_entry::collect_direct_signature() {
        byte_pattern pattern{range_};
        signature_ = pattern.create(address_);
        return !signature_.empty();
    }

    bool export_entry::collect_xref_signature() {
        xrefblk_t xref{};
        for (bool ok = xref.first_to(address_, XREF_NOFLOW | XREF_EA); ok; ok = xref.next_to()) {
            auto const source = get_item_head(xref.from);
            if (source == BADADDR || !contains_address(range_, source) || !is_code(get_flags(source))) {
                continue;
            }

            insn_t insn{};
            if (decode_insn(&insn, source) == 0) {
                continue;
            }

            transfer_data::ea_op_data operation{};
            if (!create_rip_operation(&operation, insn, address_)) {
                logging::debug("Skipped xref, unsupported address calculation: 0x{:X} -> 0x{:X}\n", source, address_);
                continue;
            }

            byte_pattern pattern{range_};
            auto signature = pattern.create(source);
            if (signature.empty()) {
                logging::debug("Skipped xref, failed to create signature: 0x{:X} -> 0x{:X}\n", source, address_);
                continue;
            }

            data_.ea_ops_chain.clear();
            data_.ea_ops_chain.push_back(operation);
            signature_ = signature;
            logging::debug(
                "Export item uses xref signature: 0x{:X} -> 0x{:X}, [{}, {}]\n",
                source,
                address_,
                operation.opcode_length,
                operation.displ_length
            );
            return true;
        }

        logging::debug("Skipped export item, no supported xref signature: 0x{:X}\n", address_);
        return false;
    }

    bool export_entry::collect_name() {
        return get_signed_name(&data_.name, address_, filter_);
    }

    bool export_entry::collect_declaration() {
        tinfo_t type{};
        if (!get_tinfo(&type, address_) || !type.is_correct()) {
            return false;
        }

        auto const* name = data_.name.empty() ? nullptr : data_.name.c_str();
        qstring declaration{};
        if (!type.print(&declaration, name, PRTYPE_1LINE | PRTYPE_SEMI) || !filter_.accept_declaration(declaration)) {
            return false;
        }

        data_.declaration = declaration;
        return true;
    }

    bool export_entry::collect_comment() {
        if (auto const func = get_func(address_); func != nullptr && func->start_ea == address_) {
            if (get_function_comment(&data_.comment, func, filter_)) {
                return true;
            }
        }

        return get_item_comment(&data_.comment, address_, filter_);
    }

    void export_entry::collect_color() {
        auto color = get_item_color(address_);

        if (color == DEFCOLOR) {
            if (auto const func = get_func(address_); func != nullptr && func->start_ea == address_) {
                color = func->color;
            }
        }

        if (color != DEFCOLOR) {
            data_.color = ida_color_to_json(color);
        }
    }

    void export_entry::collect_breakpoint() {
        bpt_t breakpoint{};
        if (!get_bpt(address_, &breakpoint)) {
            return;
        }

        data_.breakpoint.exists = true;
        data_.breakpoint.type = breakpoint.type;
        data_.breakpoint.size = breakpoint.size;
    }

    bool export_entry::has_export_data() const {
        return (options_.names && !data_.name.empty()) || !data_.declaration.empty() || !data_.comment.empty() ||
               data_.color != 0 || data_.breakpoint.exists;
    }

} // namespace omd

namespace omd::exporter {
    export_result create_transfer(const transfer_options& options, const address_region& range) {
        export_result result{};
        if (!range.valid()) {
            logging::error("Invalid export range: 0x{:X} - 0x{:X}\n", range.start, range.end);
            return result;
        }

        const auto [status, addresses] = collect_export_addresses(options, range);
        if (status == operation_status::cancelled) {
            result.status = operation_status::cancelled;
            return result;
        }

        logging::info("Export candidates: {} in range 0x{:X} - 0x{:X}\n", addresses.size(), range.start, range.end);

        for (const auto address : addresses) {
            if (user_cancelled()) {
                result.status = operation_status::cancelled;
                return result;
            }
            if (export_entry entry{address, options, range}; entry.collect()) {
                result.transfer.push_back(entry.to_json());
                logging::debug("Exported: 0x{:X}, {}\n", address, entry.get_display_name());
            }
        }

        logging::debug("Export transfer completed: {}/{} items\n", result.transfer.size(), addresses.size());
        return result;
    }

    void dump_signed_items() {
        constexpr transfer_options options{};
        const auto [start, end] = utils::get_address_range();
        auto const result = create_transfer(options, {start, end});
        if (logging::logger::instance().debug_enabled()) {
            logging::debug("{}\n", result.transfer.dump(4));
        }
    }
} // namespace omd::exporter
