#include "byte_pattern.h"
#include "pattern_search.h"

#include "../../utils/utils.h"

#include <format>

#include <bytes.hpp>
#include <funcs.hpp>

namespace omd {
    static constexpr std::size_t max_signature_size{100};

    byte_pattern::byte_pattern(const address_region range) : range_(range) {
    }

    byte_pattern& byte_pattern::add(const std::uint8_t byte, const bool is_imm) {
        bytes_.push_back(byte);
        imm_.push_back(is_imm);
        return *this;
    }

    byte_pattern& byte_pattern::trim() {
        while (!imm_.empty() && imm_.back()) {
            bytes_.pop_back();
            imm_.pop_back();
        }

        while (!imm_.empty() && imm_.front()) {
            bytes_.erase(bytes_.begin());
            imm_.erase(imm_.begin());
        }

        return *this;
    }

    byte_pattern& byte_pattern::reset() {
        bytes_.clear();
        imm_.clear();
        return *this;
    }

    std::string byte_pattern::b2s() const {
        std::string result{};
        for (std::size_t pos{}; pos < bytes_.size(); ++pos) {
            if (imm_[pos]) {
                result += "? ";
            } else {
                result += std::format("{:02X} ", static_cast<unsigned>(bytes_[pos]));
            }
        }

        if (!result.empty()) {
            result.pop_back();
        }
        return result;
    }

    std::string byte_pattern::create_linear(const ea_t start) {
        if (!range_.valid() || start < range_.start || start >= range_.end || !is_loaded(start)) {
            return {};
        }

        reset();

        const omd::pattern_search search{range_.start, range_.end};

        for (ea_t address = start; address < range_.end && is_loaded(address);) {
            insn_t insn{};
            if (decode_insn(&insn, address) == 0) {
                break;
            }

            auto const insn_end = address + insn.size;
            if (insn_end < address || insn_end > range_.end) {
                break;
            }

            if (size() + insn.size > max_signature_size) {
                break;
            }

            auto const imm_offset = utils::get_insn_imm_offset(&insn);

            for (ea_t op_addr = address; op_addr < insn_end; ++op_addr) {
                add(get_byte(op_addr), imm_offset > 0 && (op_addr - address) >= imm_offset);
            }

            byte_pattern candidate = *this;
            auto const sig = candidate.trim().b2s();

            address = insn_end;

            if (sig.empty()) {
                continue;
            }

            ea_t search_result{};
            if (auto const unique = search.search_unique(sig.c_str(), search_result);
                unique && search_result == start) {
                return sig;
            }
        }

        return {};
    }

    std::size_t byte_pattern::size() const {
        return bytes_.size();
    }

    std::string byte_pattern::create(const ea_t target) {
        if (!range_.valid() || target < range_.start || target >= range_.end) {
            return {};
        }

        auto const start = get_item_head(target);
        if (start == BADADDR || start < range_.start || start >= range_.end) {
            return {};
        }

        auto const func = get_func(start);

        if (func == nullptr) {
            return create_linear(start);
        }

        func_item_iterator_t iterator;
        if (!iterator.set(func, start)) {
            return {};
        }

        const omd::pattern_search search{range_.start, range_.end};

        reset();

        for (bool ok{true}; ok; ok = iterator.next_code()) {
            ea_t const addr = iterator.current();
            if (addr >= range_.end) {
                break;
            }

            insn_t insn{};

            if (decode_insn(&insn, addr) == 0) {
                break;
            }

            auto const insn_end = addr + insn.size;
            if (insn_end < addr || insn_end > range_.end) {
                break;
            }

            auto const imm_offset = utils::get_insn_imm_offset(&insn);

            if (size() + insn.size > max_signature_size) {
                break;
            }

            for (ea_t op_addr = addr; op_addr < insn_end; ++op_addr) {
                add(get_byte(op_addr), imm_offset > 0 && (op_addr - addr) >= imm_offset);
            }

            byte_pattern candidate = *this;
            auto const sig = candidate.trim().b2s();

            if (sig.empty()) {
                continue;
            }

            ea_t search_result{};
            if (auto const unique = search.search_unique(sig.c_str(), search_result);
                unique && search_result == start) {
                return sig;
            }
        }

        return {};
    }
} // namespace omd
