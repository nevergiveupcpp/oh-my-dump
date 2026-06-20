#ifndef NGU_OMD_UTILS_LOGGER_LOGGER_H
#define NGU_OMD_UTILS_LOGGER_LOGGER_H

#include <format>
#include <source_location>
#include <string>
#include <utility>

namespace omd::logging {
    enum class level {
        error,
        info,
        debug,
    };

    class message final {
    public:
        message(const char* format, const std::source_location& location = std::source_location::current());

        [[nodiscard]] const char* format() const;
        [[nodiscard]] const std::source_location& location() const;

    private:
        const char* format_{nullptr};
        std::source_location location_{};
    };

    class logger final {
    public:
        static logger& instance();

        void set_debug_enabled(bool enabled);
        [[nodiscard]] bool debug_enabled() const;
        [[nodiscard]] bool should_write(level severity) const;

        void write(level severity, const std::source_location& location, const std::string& text) const;

    private:
        logger() = default;

        bool debug_enabled_{false};
    };

    template<typename... Args> void write(const level severity, const message& message, Args&&... args) {
        auto& sink = logger::instance();
        if (!sink.should_write(severity)) {
            return;
        }

        auto text = std::vformat(message.format(), std::make_format_args(args...));
        sink.write(severity, message.location(), text);
    }

    template<typename... Args> void error(const message& message, Args&&... args) {
        write(level::error, message, std::forward<Args>(args)...);
    }

    template<typename... Args> void info(const message& message, Args&&... args) {
        write(level::info, message, std::forward<Args>(args)...);
    }

    template<typename... Args> void debug(const message& message, Args&&... args) {
        write(level::debug, message, std::forward<Args>(args)...);
    }
} // namespace omd::logging

#endif // NGU_OMD_UTILS_LOGGER_LOGGER_H
