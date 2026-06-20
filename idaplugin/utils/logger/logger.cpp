#include "logger.h"

#include <ida.hpp>
#include <kernwin.hpp>

namespace {
    [[nodiscard]] const char* level_label(const omd::logging::level severity) {
        switch (severity) {
        case omd::logging::level::error:
            return "ERROR";
        case omd::logging::level::info:
            return "INFO";
        case omd::logging::level::debug:
            return "DEBUG";
        default:
            return "UNKNOWN";
        }
    }
} // namespace

namespace omd::logging {
    message::message(const char* format, const std::source_location& location) : format_(format), location_(location) {
    }

    const char* message::format() const {
        return format_;
    }

    const std::source_location& message::location() const {
        return location_;
    }

    logger& logger::instance() {
        static logger instance{};
        return instance;
    }

    void logger::set_debug_enabled(const bool enabled) {
        debug_enabled_ = enabled;
    }

    bool logger::debug_enabled() const {
        return debug_enabled_;
    }

    bool logger::should_write(const level severity) const {
        return severity != level::debug || debug_enabled_;
    }

    void logger::write(const level severity, const std::source_location& location, const std::string& text) const {
        if (severity != level::debug) {
            msg("[OMD] [%s] >> %s", level_label(severity), text.c_str());
            return;
        }

        msg("[OMD] [%s] [%u:%s] >> %s",
            level_label(severity),
            static_cast<unsigned>(location.line()),
            location.function_name(),
            text.c_str());
    }
} // namespace omd::logging
