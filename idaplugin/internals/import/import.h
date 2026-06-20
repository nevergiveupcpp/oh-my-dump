#ifndef NGU_OMD_INTERNALS_IMPORT_IMPORT_H
#define NGU_OMD_INTERNALS_IMPORT_IMPORT_H

#include "internals/patterns/pattern_search.h"
#include "utils/types.h"

#include <cstddef>

#include <nlohmann/json.hpp>

namespace omd {
    class import_entry final {
    public:
        explicit import_entry(const nlohmann::json& j);

        void apply(ea_t address, const transfer_options& options) const;
        [[nodiscard]] const transfer_data& get_data() const;
        [[nodiscard]] const char* get_display_name() const;

    private:
        enum class decl_result {
            success,
            no_type_info,
            parse_failed,
            set_tinfo_failed,
        };

        enum class cmt_result {
            success,
            func_cmt_failed,
            cmt_failed,
        };

        bool adjust_address(ea_t& address) const;

        [[nodiscard]] bool set_name(ea_t address) const;
        [[nodiscard]] decl_result set_declaration(ea_t address) const;
        [[nodiscard]] cmt_result set_comment(ea_t address) const;
        [[nodiscard]] bool set_breakpoint(ea_t address) const;
        void set_color(ea_t address) const;

        transfer_data data_{};
    };
} // namespace omd

namespace omd::importer {
    struct import_result {
        operation_status status{operation_status::completed};
        std::size_t total{};
        uint32 found{};

        [[nodiscard]] std::size_t failed() const {
            return total - found;
        }
    };

    import_result apply_transfer(
        const nlohmann::json& transfer, const transfer_options& options, const address_region& range
    );
} // namespace omd::importer

#endif // NGU_OMD_INTERNALS_IMPORT_IMPORT_H
