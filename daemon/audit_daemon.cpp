
#include <csignal>
#include <climits>

#include <iostream>
#include <array>
#include <chrono>
#include <sstream>
#include <iomanip>

#include "audit_socket.hpp"

using namespace std;

constexpr const char *DEFAULT_SOCKET_PATH = "/tmp/sudo_audit.sock";

static Socket s;

void signal_handler(int signum) {
    cout << "Received signal " << signum << ", shutting down." << endl;
    s.deinit();
    exit(0);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    string_view socket_path = DEFAULT_SOCKET_PATH;

    for (int i = 1; i < argc; i++) {
        string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            cout << "Usage: " << argv[0] << endl << "\t--socket, -s <socket_path> [default: \"" << DEFAULT_SOCKET_PATH << "\"]" << endl;
            return 0;
        }
        if ((arg == "--socket" || arg == "-s") && i + 1 < argc) {
            socket_path = argv[++i];
        }
    }

    s.init(socket_path);

    cout << "Sudo audit logging daemon started at " << socket_path << endl;
    array<char, PATH_MAX*2> buffer;
    while (true) {
        auto len = s.receive(buffer.data(), buffer.size() - 1);
        if (len > 0) {
            buffer[len] = '\0'; // Ensure null-terminated
            cout << buffer.data() << endl;
        }
        else if (len < 0) {
            cerr << "Error receiving data" << endl;
        }
    }
    return 0;
}