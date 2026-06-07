#ifndef LOGGER_HPP
#define LOGGER_HPP
#pragma once

#include <functional>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace wg {

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error,
};

class Logger {
   public:
    using Sink = std::function<void(LogLevel level, std::string_view message)>;

    static Logger& default_logger() {
        static Logger logger;
        return logger;
    }

    void set_sink(Sink sink) {
        std::lock_guard<std::mutex> lock(mutex_);
        sink_ = std::move(sink);
    }

    void reset_sink() {
        std::lock_guard<std::mutex> lock(mutex_);
        sink_ = nullptr;
    }

    void set_enabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = enabled;
    }

    void log(LogLevel level, std::string_view message) {
        Sink sink;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!enabled_) {
                return;
            }
            sink = sink_;
        }

        if (sink) {
            sink(level, message);
            return;
        }

        std::lock_guard<std::mutex> lock(output_mutex_);
        std::cout << "[" << level_name(level) << "] " << message << '\n';
    }

    void debug(std::string_view message) { log(LogLevel::Debug, message); }
    void info(std::string_view message) { log(LogLevel::Info, message); }
    void warn(std::string_view message) { log(LogLevel::Warn, message); }
    void error(std::string_view message) { log(LogLevel::Error, message); }

    static std::string hex(std::span<const uint8_t> bytes) {
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (uint8_t byte : bytes) {
            out << std::setw(2) << static_cast<unsigned>(byte);
        }
        return out.str();
    }

    template <size_t N>
    static std::string hex(const std::array<uint8_t, N>& bytes) {
        return hex(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    static const char* level_name(LogLevel level) {
        switch (level) {
            case LogLevel::Debug:
                return "debug";
            case LogLevel::Info:
                return "info";
            case LogLevel::Warn:
                return "warn";
            case LogLevel::Error:
                return "error";
        }
        return "unknown";
    }

   private:
    bool enabled_ = true;
    Sink sink_;
    std::mutex mutex_;
    std::mutex output_mutex_;
};

}  // namespace wg

#endif  // LOGGER_HPP
