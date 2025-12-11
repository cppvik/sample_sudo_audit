#include <unistd.h>
#include <syslog.h>
#include <climits>
#include <sys/socket.h>
#include <sys/un.h>

#include <filesystem>
#include <unordered_set>
#include <fstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <array>
#include <vector>

#include "common.hpp"

using namespace std;

// Initialize extern variables
sudo_printf_t _sudo_plugin_printf = nullptr;
bool _enable_syslog = false;
bool _enable_stdout = false;
string _log_file = "";
string _socket_path = "";
atomic_bool _running = true;
ssize_t _child_poll_ms = 100;

static unordered_set<pid_t> children;

inline string iso_timestamp() {
    ostringstream oss;
    const auto t = chrono::system_clock::to_time_t(chrono::system_clock::now());
    oss << put_time(localtime(&t), "%FT%T%z ");
    return oss.str();
}

inline void log_audit_event(const string &log_message) {
    auto timestamp = iso_timestamp();
    if (_enable_stdout) {
        _sudo_plugin_printf(SUDO_CONV_INFO_MSG, "%s%s\n", timestamp.c_str(), log_message.c_str());
    }
    if (_enable_syslog) {
        syslog(LOG_INFO, "%s", log_message.c_str());
    }
    if (!_log_file.empty()) {
        // TODO: add flock
        ofstream log_file(_log_file, ios::app);
        if (log_file.is_open()) {
            log_file << iso_timestamp() << log_message << endl;
            log_file.close();
        }
    }
    if (!_socket_path.empty()) {
        auto socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (socket_fd == -1)
            return;

        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;

        strncpy(addr.sun_path, _socket_path.c_str(), sizeof(addr.sun_path) - 1);
        const auto final_msg = iso_timestamp() + log_message;
        sendto(socket_fd, final_msg.c_str(), final_msg.size(), 0, (struct sockaddr *)&addr, sizeof(addr));
        close(socket_fd);
    }
}

inline void report_child_processes(pid_t parent_pid, pid_t child_pid, const string &exec_file, const string &command) {
    string sppid;
    string spid;
    try {
        sppid = to_string(parent_pid);
        spid = to_string(child_pid);
    } catch (...) {
        // ignore
    }
    string log_message = "Detected child process for parent_pid=" +
        sppid +
        " | pid=" +
        spid +
        " | exe=" +
        exec_file +
        " | cmd=\'" +
        command +
        "\'";
    log_audit_event(log_message);
}

// Get command line from /proc/[pid]/cmdline
inline string get_command_line(const string &proc_path, const string &fallback) {
    const string path = proc_path + "/cmdline";
    ifstream in(path, ios::in | ios::binary);
    if (!in.is_open())
        return fallback;

    vector<char> buf((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    for (char &c : buf) {
        if (c == '\0') {
            c = ' ';
        }
    }
    in.close();
    return string(buf.begin(), buf.end() - 1); // remove trailing space
}

// Get executable path from /proc/[pid]/exe
inline string get_executable_path(const string &proc_path) {
    const filesystem::path exe_path(proc_path + "/exe");
    try {
    if (filesystem::is_symlink(exe_path))
        return filesystem::read_symlink(exe_path).string();
    } catch (...) {
        // ignore
    }
    return "";
}

void detect_child_processes(pid_t parent_pid) {
    pid_t pid;
    string command;
    char state;
    pid_t ppid;
    for (const auto& entry : filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory())
            continue;
        try {
            const auto dir_name = entry.path().filename().string();
            if (!all_of(dir_name.cbegin(), dir_name.cend(), ::isdigit))
                continue;
            const string proc_dir_path(move(entry.path().string()));
            auto status_file = proc_dir_path + "/stat";
            ifstream sf(status_file);
            if (sf.is_open()) {
                sf >> pid >> command >> state >> ppid;
                if (children.count(ppid) > 0 && children.count(pid) == 0) {
                    command = get_command_line(proc_dir_path, command);
                    auto exec_file = get_executable_path(proc_dir_path);
                    children.insert(pid);
                    report_child_processes(ppid, pid, exec_file, command);
                }
                sf.close();
            }
        } catch (...) {
            continue;
        }
    }
}

void monitor_children(pid_t parent_pid) {
    children.insert(parent_pid);
    while (_running) {
        detect_child_processes(parent_pid);
        this_thread::sleep_for(chrono::milliseconds(_child_poll_ms));
    }
}