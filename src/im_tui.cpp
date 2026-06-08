#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "core.hpp"
#include "endpoint.hpp"
#include "logger.hpp"
#include "reliable.hpp"

namespace {

struct PeerConfig {
    std::string name;
    wg::PublicKey public_key{};
    std::string address;
    uint16_t port = 0;
    wg::PreSharedKey psk{};
    bool has_psk = false;
};

struct AppConfig {
    wg::PrivateKey private_key{};
    wg::PublicKey public_key{};
    std::string bind_address = "0.0.0.0";
    uint16_t bind_port = 0;
    std::string log_file;
    std::vector<PeerConfig> peers;
};

struct ChatMessage {
    bool mine = false;
    std::string text;
};

struct PeerState {
    PeerConfig config;
    wg::Peer* peer = nullptr;
    std::vector<ChatMessage> messages;
};

std::string trim(std::string text) {
    auto is_space = [](unsigned char c) { return std::isspace(c); };
    text.erase(text.begin(),
               std::find_if(text.begin(), text.end(),
                            [&](char c) { return !is_space(c); }));
    text.erase(std::find_if(text.rbegin(), text.rend(),
                            [&](char c) { return !is_space(c); })
                   .base(),
               text.end());
    return text;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') {
        return 10 + c - 'a';
    }
    return -1;
}

bool parse_hex(std::string hex, std::span<uint8_t> out) {
    hex = trim(hex);
    if (hex.empty() || hex == "empty" || hex == "-") {
        std::fill(out.begin(), out.end(), 0);
        return true;
    }
    if (hex.size() != out.size() * 2) {
        return false;
    }
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

wg::Endpoint parse_endpoint(const std::string& address, uint16_t port) {
    if (address.find(':') != std::string::npos) {
        return wg::Endpoint::from_ipv6(address.c_str(), port);
    }
    return wg::Endpoint::from_ipv4(address.c_str(), port);
}

bool parse_boolish_empty_psk(const std::string& text) {
    const std::string value = trim(text);
    return !value.empty() && value != "empty" && value != "-" &&
           value != "null" && value != "~";
}

std::string strip_yaml_comment(const std::string& line) {
    bool single_quote = false;
    bool double_quote = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '\'' && !double_quote) {
            single_quote = !single_quote;
        } else if (c == '"' && !single_quote) {
            double_quote = !double_quote;
        } else if (c == '#' && !single_quote && !double_quote) {
            return line.substr(0, i);
        }
    }
    return line;
}

std::string unquote_yaml_scalar(std::string value) {
    value = trim(strip_yaml_comment(value));
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            value = value.substr(1, value.size() - 2);
        }
    }
    return value;
}

bool parse_yaml_key_value(const std::string& text, std::string& key,
                          std::string& value) {
    const size_t colon = text.find(':');
    if (colon == std::string::npos) {
        return false;
    }
    key = trim(text.substr(0, colon));
    value = unquote_yaml_scalar(text.substr(colon + 1));
    return !key.empty();
}

std::optional<AppConfig> load_config(const std::string& path,
                                     std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot open config: " + path;
        return std::nullopt;
    }

    enum class Section { None, Local, Peers };
    Section section = Section::None;
    AppConfig config;
    PeerConfig current_peer;
    bool have_peer = false;

    auto flush_peer = [&] {
        if (have_peer) {
            if (current_peer.name.empty()) {
                current_peer.name = "peer-" +
                                    std::to_string(config.peers.size() + 1);
            }
            config.peers.push_back(current_peer);
            current_peer = PeerConfig{};
            have_peer = false;
        }
    };

    std::string line;
    size_t line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        const std::string raw_line = strip_yaml_comment(line);
        const std::string trimmed_line = trim(raw_line);
        if (trimmed_line.empty()) {
            continue;
        }
        if (trimmed_line == "local:") {
            flush_peer();
            section = Section::Local;
            continue;
        }
        if (trimmed_line == "peers:") {
            flush_peer();
            section = Section::Peers;
            continue;
        }

        std::string key;
        std::string value;
        if (trimmed_line.rfind("- ", 0) == 0) {
            if (section != Section::Peers) {
                error = "peer item outside peers at line " +
                        std::to_string(line_no);
                return std::nullopt;
            }
            flush_peer();
            have_peer = true;
            const std::string item = trim(trimmed_line.substr(2));
            if (item.empty()) {
                continue;
            }
            if (!parse_yaml_key_value(item, key, value)) {
                error = "invalid peer item at line " + std::to_string(line_no);
                return std::nullopt;
            }
        } else {
            if (!parse_yaml_key_value(trimmed_line, key, value)) {
                error = "invalid config line " + std::to_string(line_no);
                return std::nullopt;
            }
        }

        if (section == Section::Local) {
            if (key == "private_key") {
                if (!parse_hex(value, config.private_key)) {
                    error = "invalid local private_key";
                    return std::nullopt;
                }
            } else if (key == "public_key") {
                if (!parse_hex(value, config.public_key)) {
                    error = "invalid local public_key";
                    return std::nullopt;
                }
            } else if (key == "bind_address") {
                config.bind_address = value;
            } else if (key == "bind_port") {
                config.bind_port = static_cast<uint16_t>(std::stoi(value));
            } else if (key == "log_file") {
                config.log_file = value;
            }
        } else if (section == Section::Peers && have_peer) {
            if (key == "name") {
                current_peer.name = value;
            } else if (key == "public_key") {
                if (!parse_hex(value, current_peer.public_key)) {
                    error = "invalid peer public_key";
                    return std::nullopt;
                }
            } else if (key == "address") {
                current_peer.address = value;
            } else if (key == "port") {
                current_peer.port = static_cast<uint16_t>(std::stoi(value));
            } else if (key == "psk") {
                current_peer.has_psk = parse_boolish_empty_psk(value);
                if (current_peer.has_psk &&
                    !parse_hex(value, current_peer.psk)) {
                    error = "invalid peer psk";
                    return std::nullopt;
                }
            }
        }
    }
    flush_peer();

    if (config.bind_port == 0) {
        error = "bind_port is required";
        return std::nullopt;
    }
    if (config.peers.empty()) {
        error = "at least one peer is required";
        return std::nullopt;
    }
    if (config.log_file.empty()) {
        config.log_file =
            "/tmp/nono-im-" + std::to_string(config.bind_port) + ".log";
    }
    return config;
}

class TerminalGuard {
   public:
    TerminalGuard() {
        tcgetattr(STDIN_FILENO, &old_);
        termios raw = old_;
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        std::cout << "\x1b[?1049h\x1b[?25l";
    }

    ~TerminalGuard() {
        std::cout << "\x1b[?25h\x1b[?1049l" << std::flush;
        tcsetattr(STDIN_FILENO, TCSANOW, &old_);
    }

   private:
    termios old_{};
};

struct Size {
    int rows = 24;
    int cols = 80;
};

Size terminal_size() {
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 &&
        ws.ws_row > 0) {
        return {.rows = static_cast<int>(ws.ws_row),
                .cols = static_cast<int>(ws.ws_col)};
    }
    return {};
}

std::string fit(std::string text, int width) {
    if (width <= 0) {
        return {};
    }
    if (static_cast<int>(text.size()) > width) {
        text.resize(static_cast<size_t>(std::max(0, width - 1)));
        text += "~";
    }
    if (static_cast<int>(text.size()) < width) {
        text.append(static_cast<size_t>(width - text.size()), ' ');
    }
    return text;
}

void draw(int selected, const std::vector<PeerState>& peers,
          const std::string& input, std::mutex& mutex) {
    const Size size = terminal_size();
    const int sidebar = std::min(30, std::max(20, size.cols / 4));
    const int chat_x = sidebar + 2;
    const int chat_w = std::max(20, size.cols - chat_x - 1);
    const int input_y = size.rows - 2;
    const int history_rows = std::max(3, input_y - 4);

    std::vector<ChatMessage> messages;
    std::string active_name = "none";
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!peers.empty() && selected >= 0 &&
            selected < static_cast<int>(peers.size())) {
            active_name = peers[static_cast<size_t>(selected)].config.name;
            messages = peers[static_cast<size_t>(selected)].messages;
        }
    }

    std::cout << "\x1b[H\x1b[2J";
    std::cout << "\x1b[48;5;236m\x1b[38;5;255m"
              << fit(" NONO IM  |  tab/up/down switch  enter send  q quit",
                     size.cols)
              << "\x1b[0m";

    for (int y = 2; y <= size.rows; ++y) {
        std::cout << "\x1b[" << y << ";1H\x1b[48;5;238m"
                  << fit("", sidebar) << "\x1b[0m";
    }

    std::cout << "\x1b[2;2H\x1b[38;5;245mPeers\x1b[0m";
    for (size_t i = 0; i < peers.size(); ++i) {
        const bool active = static_cast<int>(i) == selected;
        std::cout << "\x1b[" << (4 + i) << ";2H"
                  << (active ? "\x1b[48;5;39m\x1b[38;5;16m"
                             : "\x1b[48;5;238m\x1b[38;5;250m")
                  << fit((active ? "> " : "  ") + peers[i].config.name,
                         sidebar - 2)
                  << "\x1b[0m";
    }

    std::cout << "\x1b[2;" << chat_x << "H\x1b[38;5;81m" << active_name
              << "\x1b[0m";

    const int start =
        std::max(0, static_cast<int>(messages.size()) - history_rows);
    int y = 4;
    for (int i = start; i < static_cast<int>(messages.size()) && y < input_y;
         ++i, ++y) {
        const ChatMessage& msg = messages[static_cast<size_t>(i)];
        const int bubble_w = std::min(chat_w - 4, std::max(12, chat_w * 2 / 3));
        std::string text = fit(msg.text, bubble_w);
        int x = msg.mine ? chat_x + chat_w - bubble_w - 1 : chat_x;
        std::cout << "\x1b[" << y << ";" << x << "H"
                  << (msg.mine ? "\x1b[48;5;39m\x1b[38;5;16m"
                               : "\x1b[48;5;240m\x1b[38;5;255m")
                  << text << "\x1b[0m";
    }

    std::cout << "\x1b[" << (input_y - 1) << ";" << chat_x
              << "H\x1b[38;5;238m" << fit("", chat_w) << "\x1b[0m";
    std::cout << "\x1b[" << input_y << ";" << chat_x
              << "H\x1b[48;5;236m\x1b[38;5;255m"
              << fit("> " + input, chat_w) << "\x1b[0m";
    std::cout.flush();
}

void install_file_logger(const std::string& path) {
    auto file = std::make_shared<std::ofstream>(path, std::ios::app);
    auto mutex = std::make_shared<std::mutex>();
    wg::Logger::default_logger().set_sink(
        [file, mutex](wg::LogLevel level, std::string_view message) {
            std::lock_guard<std::mutex> lock(*mutex);
            (*file) << "[" << wg::Logger::level_name(level) << "] " << message
                    << '\n';
            file->flush();
        });
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " config.yaml\n";
        return 1;
    }

    std::string error;
    auto loaded = load_config(argv[1], error);
    if (!loaded) {
        std::cerr << error << "\n";
        return 1;
    }
    AppConfig config = *loaded;
    install_file_logger(config.log_file);

    wg::Core core;
    if (!core.initialize(config.private_key, config.public_key)) {
        std::cerr << "core initialize failed\n";
        return 1;
    }
    if (!core.bind(parse_endpoint(config.bind_address, config.bind_port))) {
        std::cerr << "bind failed\n";
        return 1;
    }

    std::vector<PeerState> peers;
    for (const PeerConfig& peer_config : config.peers) {
        wg::Endpoint endpoint =
            parse_endpoint(peer_config.address, peer_config.port);
        wg::Peer* peer = core.add_peer(peer_config.public_key, endpoint,
                                       peer_config.psk);
        if (peer == nullptr) {
            std::cerr << "failed to add peer: " << peer_config.name << "\n";
            return 1;
        }
        peers.push_back(PeerState{.config = peer_config, .peer = peer});
    }

    std::mutex state_mutex;
    wg::ReliableManager reliable(core, wg::ReliableConfig::fast_mode());
    reliable.set_message_callback(
        [&](wg::Peer& peer, std::span<const uint8_t> message) {
            std::string text(message.begin(), message.end());
            std::lock_guard<std::mutex> lock(state_mutex);
            for (PeerState& state : peers) {
                if (state.peer == &peer) {
                    state.messages.push_back(ChatMessage{.mine = false,
                                                         .text = text});
                    break;
                }
            }
        });

    if (!core.start()) {
        std::cerr << "core start failed\n";
        return 1;
    }

    TerminalGuard terminal;
    int selected = 0;
    std::string input;
    bool running = true;

    while (running) {
        draw(selected, peers, input, state_mutex);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        timeval tv{.tv_sec = 0, .tv_usec = 100000};
        int ready = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
        if (ready <= 0) {
            continue;
        }

        char c = 0;
        if (read(STDIN_FILENO, &c, 1) != 1) {
            continue;
        }

        if (c == 'q' && input.empty()) {
            running = false;
        } else if (c == '\t') {
            selected = peers.empty() ? 0 : (selected + 1) % peers.size();
        } else if (c == '\033') {
            char seq[2]{};
            if (read(STDIN_FILENO, seq, 2) == 2 && seq[0] == '[') {
                if (seq[1] == 'A' && selected > 0) {
                    --selected;
                } else if (seq[1] == 'B' &&
                           selected + 1 < static_cast<int>(peers.size())) {
                    ++selected;
                }
            }
        } else if (c == 127 || c == '\b') {
            if (!input.empty()) {
                input.pop_back();
            }
        } else if (c == '\n' || c == '\r') {
            if (!input.empty() && !peers.empty()) {
                PeerState& active = peers[static_cast<size_t>(selected)];
                reliable.send(
                    *active.peer,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(input.data()),
                        input.size()));
                {
                    std::lock_guard<std::mutex> lock(state_mutex);
                    active.messages.push_back(
                        ChatMessage{.mine = true, .text = input});
                }
                input.clear();
            }
        } else if (std::isprint(static_cast<unsigned char>(c))) {
            input.push_back(c);
        }
    }

    core.stop();
    return 0;
}
