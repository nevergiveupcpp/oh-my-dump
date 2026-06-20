#include "dllmain.h"

#include "version.h"
#include "dialog/dialog.h"
#include "internals/export/export.h"
#include "internals/import/import.h"
#include "utils/logger/logger.h"

#include <kernwin.hpp>
#include <loader.hpp>

namespace {
    bool perform_export(const omd::dialog::settings& settings) {
        const auto& options = settings.options;
        const auto& target_range = settings.target_range;

        omd::logging::info("Starting export in range 0x{:X} - 0x{:X}\n", target_range.start, target_range.end);

        show_wait_box("Exporting...");
        auto const result = omd::exporter::create_transfer(options, target_range);
        hide_wait_box();

        if (result.status == omd::operation_status::cancelled) {
            omd::logging::info("Export cancelled by user\n");
            return false;
        }

        if (!result.transfer.is_array()) {
            omd::logging::error("Failed to create export transfer\n");
            return false;
        }

        if (result.transfer.empty()) {
            omd::logging::error("Export transfer is empty\n");
            return false;
        }

        if (!omd::dialog::save_transfer(result.transfer)) {
            return false;
        }

        omd::logging::info("Export completed: {} items\n", result.transfer.size());
        return true;
    }

    bool perform_import(const omd::dialog::settings& settings) {
        const auto& options = settings.options;
        const auto& target_range = settings.target_range;

        auto const transfer = omd::dialog::load_transfer();

        if (!transfer.is_array()) {
            omd::logging::error("Transfer type isn't array\n");
            return false;
        }

        show_wait_box("Importing...");
        auto const result = omd::importer::apply_transfer(transfer, options, target_range);
        hide_wait_box();

        if (result.status == omd::operation_status::cancelled) {
            omd::logging::info("Import cancelled by user\n");
            return false;
        }

        if (result.total == 0) {
            omd::logging::error("Transfer contains no signatures\n");
            return false;
        }

        if (const auto failed = result.failed(); failed != 0) {
            omd::logging::error(
                "Search completed {}/{} patterns processed, {} failed\n", result.found, result.total, failed
            );
        } else {
            omd::logging::info("Search completed {}/{} patterns processed\n", result.found, result.total);
        }

        return true;
    }
} // namespace

namespace omd {
    bool plugin::run(std::size_t arg) {
        (void)arg;

        dialog::settings settings{};
        if (!dialog::ask_settings(settings)) {
            return false;
        }

        return settings.mode == dialog::operation_mode::export_signatures ? perform_export(settings)
                                                                          : perform_import(settings);
    }

    plugmod_t* idaapi init() {
        return new plugin();
    }

} // namespace omd

plugin_t PLUGIN{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    omd::init,
    nullptr,
    nullptr,
    PLUGIN_NAME " v" PLUGIN_VERSION " for IDA Pro 9.x by nevergiveupcpp",
    "1. Run the plugin.\n"
    "2. Choose operation, target scope, fields and debug output in the settings dialog.\n"
    "3. For import choose input *.json; for export choose output *.json.\n"
    "4. Wait for the operation to complete.",
    PLUGIN_NAME,
    PLUGIN_HOTKEY
};
