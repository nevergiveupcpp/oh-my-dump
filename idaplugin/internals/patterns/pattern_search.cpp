#include "pattern_search.h"

#include "../../utils/logger/logger.h"

#include <bytes.hpp>
#include <search.hpp>

namespace omd {
    pattern_search::pattern_search(const ea_t start, const ea_t end) {
        region_.start = start;
        region_.end = end;
    }

    operation_status pattern_search::run(uint32* found) {
        for (const auto& [sig, callback] : patterns_) {
            if (search(sig, callback) == BADADDR) {
                logging::debug("Pattern not found: {}\n", sig.c_str());
            } else if (found != nullptr) {
                ++*found;
            }
        }

        clear();
        return operation_status::completed;
    }

    void pattern_search::add(const qstring& sig, const on_found_callback& callback) {
        patterns_.emplace_back(pattern_entry{sig, callback});
    }

    void pattern_search::clear() {
        patterns_.clear();
    }

    ea_t pattern_search::search(const qstring& sig, const on_found_callback& callback) const {
        auto const address = impl_search(sig, region_);

        if (callback != nullptr) {
            callback(address);
        }

        return address;
    }

    bool pattern_search::search_unique(
        const qstring& sig, ea_t& address_found, const on_found_callback& callback
    ) const {
        address_found = impl_search(sig, region_);

        if (address_found == BADADDR) {
            return false;
        }

        if (auto const next = impl_search(sig, {address_found + 1, region_.end}); next == BADADDR) {
            if (callback != nullptr) {
                callback(address_found);
            }
            return true;
        }

        return false;
    }

    ea_t pattern_search::impl_search(const qstring& sig, const address_region& reg) const {
#if IDA_SDK_VERSION >= 900
        compiled_binpat_vec_t binary_pattern{};
        if (!parse_binpat_str(&binary_pattern, reg.start, sig.c_str(), 16)) {
            return BADADDR;
        }
        return bin_search(reg.start, reg.end, binary_pattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD);
#else
        return find_binary(reg.start, reg.end, sig.c_str(), 16, SEARCH_DOWN);
#endif
    }
} // namespace omd
