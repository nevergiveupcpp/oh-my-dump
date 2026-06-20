#ifndef NGU_OMD_INTERNALS_EXPORT_EXPORT_H
#define NGU_OMD_INTERNALS_EXPORT_EXPORT_H

#include "utils/types.h"

#include <string>

#include <nlohmann/json.hpp>

namespace omd {
    struct filter_options {
        bool enabled{true};
    };

    class export_filter final {
    public:
        explicit export_filter(const filter_options options = {}) : options_(options) {
        }

        [[nodiscard]] bool accept_name(ea_t address, const qstring& name) const;
        [[nodiscard]] bool accept_declaration(const qstring& declaration) const;
        [[nodiscard]] bool accept_comment(const qstring& comment) const;

    private:
        filter_options options_{};
    };

    class export_entry final {
    public:
        export_entry(ea_t address, const transfer_options& options, const address_region& range);

        bool collect();
        [[nodiscard]] nlohmann::ordered_json to_json() const;
        [[nodiscard]] const transfer_data& get_data() const;
        [[nodiscard]] const char* get_display_name() const;

    private:
        bool collect_signature();
        bool collect_direct_signature();
        bool collect_xref_signature();
        bool collect_name();
        bool collect_declaration();
        bool collect_comment();
        void collect_color();
        void collect_breakpoint();

        [[nodiscard]] bool has_export_data() const;

        ea_t address_{BADADDR};
        address_region range_{};
        transfer_options options_{};
        export_filter filter_{};
        std::string signature_{};
        transfer_data data_{};
    };

} // namespace omd

namespace omd::exporter {
    struct export_result {
        operation_status status{operation_status::completed};
        nlohmann::ordered_json transfer{nlohmann::ordered_json::array()};
    };

    export_result create_transfer(const transfer_options& options, const address_region& range);
    void dump_signed_items();
} // namespace omd::exporter

#endif // NGU_OMD_INTERNALS_EXPORT_EXPORT_H
