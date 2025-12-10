#include <cstdio>
#include <cstring>

#include <memory>
#include <array>
#include <fstream>
#include <thread>

#include "common.hpp"

#define WHICH_CMD "which "

using namespace std;

thread child_monitor_thread;

extern "C" {
    static int open_audit(unsigned int version, sudo_conv_t conversation,
                          sudo_printf_t sudo_plugin_printf, char *const settings[],
                          char *const user_info[], int submit_optind,
                          char *const submit_argv[], char *const submit_envp[],
                          char *const plugin_options[], const char **errstr) {
        _sudo_plugin_printf = sudo_plugin_printf;
        string log_message = "sudo command: ";
        if (submit_argv[1] != nullptr) {
            array<char, PATH_MAX> buffer;
            char *read_result = nullptr;
            int status = -1;
            string which_cmd = WHICH_CMD + string(submit_argv[1]);

            FILE *fp = popen(which_cmd.c_str(), "r");
            if (fp != nullptr) {
                read_result = fgets(buffer.data(), PATH_MAX, fp);
                status = pclose(fp);
            }
            if (status == 0 && read_result != nullptr) {
                log_message += buffer.data();
                log_message.erase(log_message.find_last_not_of("\n") + 1);
            } else {
                log_message += submit_argv[1];
            }

            for (int i = 2; submit_argv[i] != nullptr; i++) {
                log_message += " " + string(submit_argv[i]);
            }
        }

        for (int i = 0; plugin_options[i] != nullptr; i++) {
            string option(plugin_options[i]);
            if (option == "enable_stdout=true") {
                _enable_stdout = true;
            } else if (option == "enable_syslog=true") {
                _enable_syslog = true;
            } else if (option.find("log_file=") == 0) {
                _log_file = option.substr(strlen("log_file="));
            } else if (option.find("child_poll_ms=") == 0) {
                string poll_str = option.substr(strlen("child_poll_ms="));
                try {
                    child_poll_ms = stoi(poll_str);
                } catch (const invalid_argument &e) {
                    string err = "Invalid child_poll_ms value: " + poll_str;
                    *errstr = strdup(err.c_str());
                    return -1;
                }
            }
        }

        for (int i = 0; user_info[i] != nullptr; i++) {
            string ui(user_info[i]);

            if (ui.find("pid") == 0) {
                string pid_s = ui.substr(ui.find('=') + 1);
                pid_t parent_pid;
                try {
                    parent_pid = stoi(pid_s);
                }
                catch (const invalid_argument &e) {
                    return -1;
                }
                child_monitor_thread = thread(monitor_children, parent_pid);
                log_message += "| pid=" + pid_s + " ";
            } else if (ui.find("ppid") == 0) {
                log_message += "| ppid=" + ui.substr(ui.find('=') + 1) + " ";
            } else if (ui.find("uid") == 0) {
                log_message += "| uid=" + ui.substr(ui.find('=') + 1) + " ";
            } else if (ui.find("gid") == 0) {
                log_message += "| gid=" + ui.substr(ui.find('=') + 1) + " ";
            } else if (ui.find("user") == 0) {
                log_message += "| user=" + ui.substr(ui.find('=') + 1) + " ";
            }
        }

        if (_enable_stdout) {
            _sudo_plugin_printf(SUDO_CONV_INFO_MSG, "%s\n", log_message.c_str());
        }
        if (_enable_syslog) {
            openlog("sudo_audit", LOG_PID, LOG_AUTH);
            syslog(LOG_INFO, "%s", log_message.c_str());
        }
        if (!_log_file.empty()) {
            ofstream log_file(_log_file, ios::app);
            if (log_file.is_open()) {
                log_file << iso_timestamp() << " " << log_message << "\n";
                log_file.close();
            } else {
                string err = "Failed to open log file: " + _log_file;
                *errstr = strdup(err.c_str());
                return -1;
            }
        }
        return 1;
    }

    static void close_audit(int status_type, int status) {
        _running = false;
        if (child_monitor_thread.joinable()) {
            child_monitor_thread.join();
        }
        closelog();
    }

    struct audit_plugin sudo_audit = {
        SUDO_AUDIT_PLUGIN,
        SUDO_API_VERSION,
        /* open */
        open_audit,
        /* close */
        close_audit,
        /* accept */
        nullptr,
        /* reject */
        nullptr,
        /* error */
        nullptr,
        /* show_version */
        nullptr,
        /* register_hooks */
        nullptr,
        /* deregister_hooks */
        nullptr,
        /* event_alloc */
        nullptr,
    };

} // extern "C"