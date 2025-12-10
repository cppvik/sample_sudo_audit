#include <filesystem>
#include <unordered_set>
#include <fstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <array>
#include <vector>
#include <unistd.h>

#include "common.hpp"

using namespace std;

sudo_printf_t _sudo_plugin_printf = nullptr;
bool _enable_syslog = false;
bool _enable_stdout = false;
string _log_file = "";
atomic_bool _running = true;
ssize_t child_poll_ms = 100;

static unordered_set<pid_t> children;

string iso_timestamp() {
    time_t t = time(nullptr);
    tm tm;
    localtime_r(&t, &tm);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return string(buf);
}

void report_child_processes(pid_t parent_pid, pid_t child_pid, const string &exec_file, const string &command) {
    string log_message = "Detected child process for parent pid=" +
        to_string(parent_pid) +
        ": [pid=" +
        to_string(child_pid) +
        " | exe=" +
        exec_file +
        " | cmd=\'" +
        command +
        "\']";

    if (_enable_stdout) {
        _sudo_plugin_printf(SUDO_CONV_INFO_MSG, "%s\n", log_message.c_str());
    }
    if (_enable_syslog) {
        syslog(LOG_INFO, "%s", log_message.c_str());
    }
    if (!_log_file.empty()) {
        ofstream log_file(_log_file, ios::app);
        if (log_file.is_open()) {
            log_file << iso_timestamp() << " " << log_message << endl;
            log_file.close();
        }
    }
}

inline string get_command_line(string entry_path, string fallback) {
    string path = entry_path + "/cmdline";
    ifstream in(path, ios::in | ios::binary);
    if (!in) {
        return fallback;
    }

    vector<char> buf((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    for (char &c : buf) {
        if (c == '\0') {
            c = ' ';
        }
    }
    return string(buf.begin(), buf.end() - 1); // remove trailing space
}

inline string get_executable_path(string entry_path) {
    string exe_path = entry_path + "/exe";
    array<char, PATH_MAX> buffer;
    ssize_t len = readlink(exe_path.c_str(), buffer.data(), buffer.size() - 1);
    if (len != -1) {
        buffer[len] = '\0';
        return string(buffer.data());
    }
    return "";
}

void detect_child_processes(pid_t parent_pid) {
    static pid_t pid;
    static string command;
    static char state;
    static pid_t ppid;
    for (const auto& entry : filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            string dir_name = entry.path().filename().string();
            if (all_of(dir_name.begin(), dir_name.end(), ::isdigit)) {
                string status_file = entry.path().string() + "/stat";
                ifstream sf(status_file);
                if (sf.is_open()) {
                    sf >> pid >> command >> state >> ppid;
                    if (children.count(ppid) > 0 && children.count(pid) == 0) {
                        command = get_command_line(entry.path().string(), command);
                        string exec_file = get_executable_path(entry.path().string());
                        children.insert(pid);
                        report_child_processes(ppid, pid, exec_file, command);
                    }
                    sf.close();
                }
            }
        }
    }
}

void monitor_children(pid_t parent_pid) {
    children.insert(parent_pid);
    while (_running) {
        detect_child_processes(parent_pid);
        this_thread::sleep_for(chrono::milliseconds(child_poll_ms));
    }
}