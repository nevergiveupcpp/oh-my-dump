#ifndef NGU_OMD_INTERNALS_PATTERNS_PATTERN_SEARCH_H
#define NGU_OMD_INTERNALS_PATTERNS_PATTERN_SEARCH_H

#include "utils/types.h"

#include <functional>
#include <vector>

#include <ida.hpp>

namespace omd {
    class pattern_search final {
        using on_found_callback = std::function<void(ea_t)>;

        struct pattern_entry {
            qstring sig{};
            on_found_callback callback{};
        };

    public:
        pattern_search(ea_t start, ea_t end);

        operation_status run(uint32* found = nullptr);
        void add(const qstring& sig, const on_found_callback& callback = nullptr);
        void clear();

        [[nodiscard]] ea_t search(const qstring& sig, const on_found_callback& callback = nullptr) const;
        [[nodiscard]] bool search_unique(
            const qstring& sig, ea_t& address_found, const on_found_callback& callback = nullptr
        ) const;

    private:
        [[nodiscard]] ea_t impl_search(const qstring& sig, const address_region& reg) const;

        address_region region_{};
        std::vector<pattern_entry> patterns_{};
    };
} // namespace omd

#endif // NGU_OMD_INTERNALS_PATTERNS_PATTERN_SEARCH_H
