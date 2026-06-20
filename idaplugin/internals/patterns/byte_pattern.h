#ifndef NGU_OMD_INTERNALS_PATTERNS_BYTE_PATTERN_H
#define NGU_OMD_INTERNALS_PATTERNS_BYTE_PATTERN_H

#include "utils/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <ida.hpp>

namespace omd {
    class byte_pattern final {
    public:
        explicit byte_pattern(address_region range);

        [[nodiscard]] std::string create(ea_t target);

    private:
        byte_pattern& add(std::uint8_t byte, bool is_imm = false);
        byte_pattern& trim();
        byte_pattern& reset();

        [[nodiscard]] std::string b2s() const;
        [[nodiscard]] std::string create_linear(ea_t start);
        [[nodiscard]] std::size_t size() const;

        address_region range_{};
        std::vector<std::uint8_t> bytes_;
        std::vector<bool> imm_;
    };
} // namespace omd

#endif // NGU_OMD_INTERNALS_PATTERNS_BYTE_PATTERN_H
