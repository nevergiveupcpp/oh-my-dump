#ifndef NGU_OMD_UTILS_TYPES_H
#define NGU_OMD_UTILS_TYPES_H

#include <cstddef>
#include <cstdint>
#include <string>

#include <ida.hpp>
#include <idd.hpp>

namespace omd {
    constexpr std::size_t max_bpt_array_size{3};
    constexpr std::size_t max_insn_layout_array_size{2};

    enum class operation_status {
        completed,
        cancelled,
    };

    enum op_type { ea_calc, addr_calc };

    enum insn_array_idx {
        opcode_length,
        displ_length,
    };

    enum bpt_array_idx {
        breakpoint_exists,
        breakpoint_type,
        breakpoint_size,
    };

    class bitmask {
    public:
        explicit bitmask(const ushort value) : bits_(value) {
        }

        bool set(const ushort bit) {
            return (bits_ |= (1U << bit)) != 0u;
        }

        bool reset(const ushort bit) {
            return (bits_ &= ~(1U << bit)) != 0u;
        }

        bool is_bit_set(const ushort bit) const {
            return (bits_ & (1U << bit)) != 0;
        }

        bool any_bit() const {
            return bits_ != 0;
        }

        explicit operator ushort() const {
            return bits_;
        }

    private:
        ushort bits_{};
    };

    struct transfer_data {
        struct ea_op_data {
            op_type type{};
            std::int64_t offset{0};
            std::uint32_t opcode_length{0};
            std::uint32_t displ_length{0};
        };
        struct bpt_data {
            bool exists{};
            bpttype_t type{};
            asize_t size{};
        };

        qstring name{};
        qstring declaration{};
        qstring comment{};
        std::uint32_t color{0};
        qvector<ea_op_data> ea_ops_chain{};
        bpt_data breakpoint{};
    };

    struct transfer_options {
        bool names{true};
        bool declarations{true};
        bool comments{true};
        bool colors{true};
        bool breakpoints{true};

        bool filter_noise{true};

        [[nodiscard]] bool any() const {
            return names || declarations || comments || colors || breakpoints;
        }
    };

    struct address_region {
        address_region() = default;
        explicit address_region(const std::pair<ea_t, ea_t>& range) : start(range.first), end(range.second) {};
        address_region(const ea_t start, const ea_t end) : start(start), end(end) {};

        address_region& operator=(const std::pair<ea_t, ea_t>& range) {
            start = range.first;
            end = range.second;
            return *this;
        }

        ea_t start{BADADDR};
        ea_t end{BADADDR};

        [[nodiscard]] bool valid() const {
            return start != BADADDR && end != BADADDR && start < end;
        }
    };
} // namespace omd

#endif // NGU_OMD_UTILS_TYPES_H
