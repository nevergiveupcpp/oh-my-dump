#include "dialog/dialog.h"

#include "version.h"
#include "../utils/logger/logger.h"
#include "../utils/utils.h"

#include <filesystem>
#include <sstream>
#include <string>

#include <fpro.h>
#include <kernwin.hpp>
#include <nalt.hpp>
#include <segment.hpp>

namespace {
    enum transfer_field : ushort {
        transfer_names = 0,
        transfer_declarations,
        transfer_comments,
        transfer_colors,
        transfer_breakpoints
    };

    enum additional_options : ushort { debug_output = 0, export_filter };

    std::string default_transfer_filename() {
        char root_filename[QMAXPATH]{};
        get_root_filename(root_filename, sizeof(root_filename));

        const std::filesystem::path filename{root_filename};
        return filename.stem().string() + ".omd.json";
    }

    [[nodiscard]] bool ask_named_segment_range(omd::address_region& target_range) {
        qstring segment_name{".text"};

        if (!ask_str(&segment_name, HIST_SEG, "Enter segment name")) {
            omd::logging::error("Failed to get segment name from dialog widget\n");
            return false;
        }

        auto const segment = get_segm_by_name(segment_name.c_str());
        if (segment == nullptr) {
            omd::logging::error("Failed to get segment: {}\n", segment_name.c_str());
            return false;
        }

        target_range = omd::address_region{segment->start_ea, segment->end_ea};
        if (!target_range.valid()) {
            omd::logging::error(
                "Invalid segment range for {}: 0x{:X} - 0x{:X}\n",
                segment_name.c_str(),
                target_range.start,
                target_range.end
            );
            return false;
        }

        return true;
    }

    [[nodiscard]] bool ask_custom_address_range(omd::address_region& target_range) {
        const auto [ea_min, ea_max] = omd::utils::get_address_range();
        ea_t start_address{ea_min};
        ea_t end_address{ea_max};

        constexpr char custom_address_range_form_body[] = "<~S~tart address:$::16::>\n"
                                                          "<~E~nd address  :$::16::>\n";

        std::stringstream custom_address_range_form;
        custom_address_range_form << PLUGIN_NAME ": Custom address range\n";
        custom_address_range_form << custom_address_range_form_body;

        if (ask_form(custom_address_range_form.str().c_str(), &start_address, &end_address) <= 0) {
            omd::logging::error("Failed to get custom range from dialog widget\n");
            return false;
        }

        target_range = omd::address_region{start_address, end_address};
        if (!target_range.valid()) {
            omd::logging::error("Invalid custom range: 0x{:X} - 0x{:X}\n", start_address, end_address);
            return false;
        }

        return true;
    }

    [[nodiscard]] bool ask_target_range(omd::address_region& target_range, const ushort selected_scope) {
        if (selected_scope == omd::dialog::target_scope::whole_database) {
            const auto [ea_min, ea_max] = omd::utils::get_address_range();
            target_range = omd::address_region{ea_min, ea_max};
        } else if (selected_scope == omd::dialog::target_scope::named_segment) {
            return ask_named_segment_range(target_range);
        } else if (selected_scope == omd::dialog::target_scope::custom_address_range) {
            return ask_custom_address_range(target_range);
        }

        if (!target_range.valid()) {
            omd::logging::error("Failed to get working range\n");
            return false;
        }

        return true;
    }

} // namespace

namespace omd::dialog {
    nlohmann::json load_transfer() {
        auto const path = ask_file(false, default_transfer_filename().c_str(), "Choose transfer file");

        if (path == nullptr) {
            logging::error("Failed to get a file name from dialog widget\n");
            return nlohmann::json{};
        }

        return utils::read_json(path);
    }

    bool save_transfer(const nlohmann::ordered_json& transfer) {
        auto const path = ask_file(true, default_transfer_filename().c_str(), "Save transfer");

        if (path == nullptr) {
            logging::error("Failed to get output file name from dialog widget\n");
            return false;
        }

        return utils::write_json(path, transfer);
    }

    bool ask_settings(settings& settings) {
        ushort selected_mode{operation_mode::export_signatures};
        ushort selected_scope{target_scope::named_segment};

        omd::bitmask field_mask{
            (1 << transfer_names) | (1 << transfer_declarations) | (1 << transfer_comments) | (1 << transfer_colors) |
            (1 << transfer_breakpoints)
        };
        omd::bitmask other_mask{(1 << export_filter)};

        constexpr char settings_form_body[] =
            "Operation:\n"
            "<#Exports all signatures to a file#~E~xport signatures:R>\n"
            "<#Import all signatures from your file#~I~mport signatures:R>>\n"

            "Target scope:\n"
            "<#Search the entire database and all loaded segments#~G~lobal (search in entire binary):R>\n"
            "<#Search only within the currently selected segment (recommended)#~S~egment only (search in selected "
            "segment, recommended):R>\n"
            "<#Search within a user-specified address range#~C~ustom (search within range):R>>\n"

            "Included fields:\n"
            "<#Include function and symbol names in the signature data#~N~ames:C>\n"
            "<#Include type information and declarations#~D~eclarations:C>\n"
            "<#Include repeatable and non-repeatable comments#Co~m~ments:C>\n"
            "<#Include item and background colors#C~o~lors:C>\n"
            "<#Include breakpoint locations and settings#~B~reakpoints:C>>\n"

            "Additional options:\n"
            "<#Print detailed diagnostic information to the output window#D~e~bug output:C>\n"
            "<#Skip autogenerated names, comments, and other automatically created data#~F~ilter autogenerated "
            "data:C>>\n";

        std::stringstream settings_form;
        settings_form << PLUGIN_NAME " v" PLUGIN_VERSION;
        settings_form << "\n";
        settings_form << settings_form_body;

        if (ask_form(settings_form.str().c_str(), &selected_mode, &selected_scope, &field_mask, &other_mask) <= 0) {
            return false;
        }

        settings.mode = static_cast<operation_mode>(selected_mode);
        settings.options.names = field_mask.is_bit_set(transfer_names);
        settings.options.declarations = field_mask.is_bit_set(transfer_declarations);
        settings.options.comments = field_mask.is_bit_set(transfer_comments);
        settings.options.colors = field_mask.is_bit_set(transfer_colors);
        settings.options.breakpoints = field_mask.is_bit_set(transfer_breakpoints);
        settings.options.filter_noise = other_mask.is_bit_set(export_filter);

        logging::logger::instance().set_debug_enabled(other_mask.is_bit_set(debug_output));

        if (!settings.options.any()) {
            logging::error("No fields selected\n");
            return false;
        }

        if (!ask_target_range(settings.target_range, selected_scope)) {
            return false;
        }

        return true;
    }
} // namespace omd::dialog
