#include "utils/utils.h"

#include "logger/logger.h"

#include <bytes.hpp>
#include <fpro.h>

namespace omd::utils {
    nlohmann::json read_json(const char* path) {
        auto const file = qfopen(path, "rb");

        if (file == nullptr) {
            logging::error("Failed to get a file\n");
            return nlohmann::json{};
        }

        auto const size = qfsize(file);

        if (size == 0) {
            logging::error("Empty file received\n");
            qfclose(file);
            return nlohmann::json{};
        };

        std::vector<char> buffer(size + 1);
        if (auto const bytes_read = qfread(file, buffer.data(), size); bytes_read != size) {
            logging::error("Failed to read complete file: read {} bytes, expected {}\n", bytes_read, size);
            qfclose(file);
            return nlohmann::json{};
        }
        buffer[size] = '\0';
        qfclose(file);

        try {
            return nlohmann::json::parse(buffer.data());
        } catch (const nlohmann::json::parse_error& e) {
            logging::error("Failed to parse json: {}\n", e.what());
            return nlohmann::json{};
        }
    }

    bool write_json(const char* path, const nlohmann::ordered_json& json) {
        auto const file = qfopen(path, "wb");

        if (file == nullptr) {
            logging::error("Failed to create output file\n");
            return false;
        }

        auto const contents = json.dump(4);
        auto const bytes_written = qfwrite(file, contents.data(), contents.size());
        qfclose(file);

        if (bytes_written != contents.size()) {
            logging::error(
                "Failed to write complete file: wrote {} bytes, expected {}\n", bytes_written, contents.size()
            );
            return false;
        }

        return true;
    }

    std::pair<ea_t, ea_t> get_address_range() {
        return {inf_get_min_ea(), inf_get_max_ea()};
    }

    bool has_type_info(const ea_t address) {
        auto const flags = get_flags(address);
        return is_func(flags) || is_data(flags) || is_unknown(flags);
    }

    std::int32_t get_insn_imm_offset(insn_t const* insn) {
        for (std::uint32_t i{}; i < UA_MAXOP; i++) {
            op_t const* op = &insn->ops[i];

            if (op->type == o_void) {
                return 0;
            }

            if (op->offb > 0) {
                return op->offb;
            }
        }
        return 0;
    }
} // namespace omd::utils
