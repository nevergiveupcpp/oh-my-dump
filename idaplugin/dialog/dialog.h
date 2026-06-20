#ifndef NGU_OMD_DIALOG_DIALOG_H
#define NGU_OMD_DIALOG_DIALOG_H

#include "utils/types.h"

#include <nlohmann/json.hpp>

namespace omd::dialog {
    enum operation_mode : ushort {
        export_signatures,
        import_signatures,
    };

    enum target_scope : ushort {
        whole_database,
        named_segment,
        custom_address_range,
    };

    struct settings {
        operation_mode mode{operation_mode::export_signatures};
        transfer_options options{};
        address_region target_range{};
    };

    nlohmann::json load_transfer();
    bool save_transfer(const nlohmann::ordered_json& transfer);
    bool ask_settings(settings& settings);
} // namespace omd::dialog

#endif // NGU_OMD_DIALOG_DIALOG_H
