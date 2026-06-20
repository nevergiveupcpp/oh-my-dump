#ifndef NGU_OMD_UTILS_UTILS_H
#define NGU_OMD_UTILS_UTILS_H

#include <cstdint>
#include <utility>

#include <nlohmann/json.hpp>

#include <ida.hpp>
#include <ua.hpp>

namespace omd::utils {
    nlohmann::json read_json(const char* path);

    bool write_json(const char* path, const nlohmann::ordered_json& json);

    std::pair<ea_t, ea_t> get_address_range();

    bool has_type_info(ea_t address);

    std::int32_t get_insn_imm_offset(insn_t const* insn);
} // namespace omd::utils

#endif // NGU_OMD_UTILS_UTILS_H
