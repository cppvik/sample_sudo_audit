#include <cstdio>
#include <cstring>
#include <climits>
#include <syslog.h>

#include <memory>
#include <array>
#include <fstream>
#include <thread>
#include <charconv>
#include <filesystem>

#include "common.hpp"

#define WHICH_CMD "which "

using namespace std;

static thread child_monitor_thread;

extern "C" {
    static int open_audit(unsigned int version, sudo_conv_t conversation,
                          sudo_printf_t sudo_plugin_printf, char *const settings[],
                          char *const user_info[], int submit_optind,
                          char *const submit_argv[], char *const submit_envp[],
                          char *const plugin_options[], const char **errstr) {
        _sudo_plugin_printf = sudo_plugin_printf;
        string log_message = "sudo command: ";

        // Try to find the target in PATH and resolve its absolute path
        if (submit_argv[1] != nullptr) {
            array<char, PATH_MAX> buffer;
            char *read_result = nullptr;
            int status = -1;
            string which_cmd = WHICH_CMD + string(submit_argv[1]);
            string resolved_path;

            /*
            * Can be rewritten with boost:process
            * Decided to keep it simple to avoid dependency
            * <victor.kartashov@gmail.com>
            */
            FILE *fp = popen(which_cmd.c_str(), "r");
            if (fp != nullptr) {
                read_result = fgets(buffer.data(), PATH_MAX, fp);
                status = pclose(fp);
            }
            if (status == 0 && read_result != nullptr) {
                resolved_path = read_result;
                resolved_path.erase(resolved_path.find_last_not_of("\n") + 1);
            } else {
                resolved_path  = submit_argv[1];
            }
            
            try {
                resolved_path = filesystem::canonical(resolved_path).string();
                log_message += "exe=" +resolved_path + " ";
            } catch (const filesystem::filesystem_error &e) {
                *errstr = strdup(e.what());
                return -1;
            }

            string args;
            for (int i = 2; submit_argv[i] != nullptr; i++) {
                if (i > 2)
                    args += " ";
                args += submit_argv[i];
            }
            if (!args.empty()) {
                log_message += "| args=\'" + args + "\' ";
            }
        } else {
            log_message += "<UNKNOWN> ";
        }

        // Parse plugin options
        for (int i = 0; plugin_options[i] != nullptr; i++) {
            string_view option(plugin_options[i]);

            if (option == "enable_stdout=true") {
                _enable_stdout = true;
            } else if (option == "enable_syslog=true") {
                openlog("sudo_audit", LOG_PID, LOG_AUTH);
                _enable_syslog = true;
            } else if (option.find("log_file=") == 0) {
                _log_file = option.substr(strlen("log_file="));
            } else if (option.find("child_poll_ms=") == 0) {
                string_view poll_str = option.substr(strlen("child_poll_ms="));
                auto result = from_chars(poll_str.data(), poll_str.data() + poll_str.size(), _child_poll_ms);
                if (result.ec == errc::invalid_argument) {
                    string err = "Invalid child_poll_ms value: " + string(poll_str);
                    *errstr = strdup(err.c_str());
                    return -1;
                }
            } else if (option.find("socket_path=") == 0) {
                _socket_path = option.substr(strlen("socket_path="));
            }
        }

        // Parse user and process info
        for (int i = 0; user_info[i] != nullptr; i++) {
            string_view ui(user_info[i]);

            if (ui.find("pid=") == 0) {
                pid_t parent_pid;
                string_view pid_s = ui.substr(strlen("pid="));
                auto result = from_chars(pid_s.data(), pid_s.data() + pid_s.size(), parent_pid);
                if (result.ec == errc::invalid_argument) {
                    string err = "Invalid pid value: " + string(pid_s);
                    *errstr = strdup(err.c_str());
                    return -1;
                } else if (result.ec == errc::result_out_of_range) {
                    string err = "Out of range pid value: " + string(pid_s);
                    *errstr = strdup(err.c_str());
                    return -1;
                }
                child_monitor_thread = thread(monitor_children, parent_pid);
                log_message += "| pid=";
                log_message += pid_s;
                log_message += " ";
            }
            else if (ui.find("ppid=") == 0) {
                log_message += "| ppid=";
                log_message += ui.substr(strlen("ppid="));
                log_message += " ";
            }
            else if (ui.find("uid=") == 0) {
                log_message += "| uid=";
                log_message += ui.substr(strlen("uid="));
                log_message += " ";
            }
            else if (ui.find("gid=") == 0) {
                log_message += "| gid=";
                log_message += ui.substr(strlen("gid="));
                log_message += " ";
            }
            else if (ui.find("user=") == 0) {
                log_message += "| user=";
                log_message += ui.substr(strlen("user="));
                log_message += " ";
            }
        }

        log_audit_event(log_message);
        return 1;
    }

    static void close_audit(int status_type, int status) {
        _running = false;
        if (child_monitor_thread.joinable())
            child_monitor_thread.join();
        if (_enable_syslog)
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