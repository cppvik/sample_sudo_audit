#define restrict __restrict__ 
#include<sudo_plugin.h>
#include <syslog.h>

#include <cstdio>
#include <cstring>

#include <string>
#include <memory>
#include <array>
#include <fstream>


#define PATH_MAX 4096UL
#define WHICH_CMD "which "

extern "C"
{
    static int open_audit(unsigned int version, sudo_conv_t conversation,
                          sudo_printf_t sudo_plugin_printf, char *const settings[],
                          char *const user_info[], int submit_optind,
                          char *const submit_argv[], char *const submit_envp[],
                          char *const plugin_options[], const char **errstr) {
        std::string log_message = "sudo command: ";
        if (submit_argv[1] != nullptr) {
            std::array<char, PATH_MAX> buffer;
            char *read_result = nullptr;
            int status = -1;
            std::string which_cmd = WHICH_CMD + std::string(submit_argv[1]);

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

            for (int i = 2; submit_argv[i] != nullptr; ++i) {
                log_message += " " + std::string(submit_argv[i]);
            }
        }

        for (int i = 0; user_info[i] != nullptr; ++i) {
            std::string ui(user_info[i]);
            std::string token = ui.substr(0, ui.find('='));
            std::string value = ui.substr(ui.find('=') + 1);

            if (token == "pid") {
                log_message += "| pid=" + value + " ";
            } else if (token == "ppid") {
                log_message += "| ppid=" + value + " ";
            } else if (token == "uid") {
                log_message += "| uid=" + value + " ";
            } else if (token == "gid") {
                log_message += "| gid=" + value + " ";
            } else if (token == "user") {
                log_message += "| user=" + value + " ";
            }
        }

        for (int i = 0; plugin_options[i] != nullptr; ++i) {
            std::string option(plugin_options[i]);
            std::string token = option.substr(0, option.find('='));
            std::string value = option.substr(option.find('=') + 1);

            if (token == "enable_stdout" && value == "true") {
                sudo_plugin_printf(SUDO_CONV_INFO_MSG, "%s\n", log_message.c_str());
            } else if (token == "enable_syslog" && value == "true") {
                openlog("sudo_cpp_audit", LOG_PID, LOG_AUTH);
                syslog(LOG_INFO, "%s", log_message.c_str());
            } else if (token == "log_file") {
                std::ofstream log_file(value, std::ios::app);
                if (log_file.is_open()) {
                    log_file << log_message << "\n";
                    log_file.close();
                } else {
                    std::string err = "Failed to open log file: " + value;
                    *errstr = strdup(err.c_str());
                    return -1;
                }
            }
        }
        return 1;
    }

    static void close_audit(int status_type, int status) {
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