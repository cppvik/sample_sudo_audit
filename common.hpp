#pragma once
#define restrict __restrict__
#include <sudo_plugin.h>
#include <atomic>
#include <string>

extern sudo_printf_t _sudo_plugin_printf;
extern bool _enable_syslog;
extern bool _enable_stdout;
extern std::string _log_file;
extern ssize_t _child_poll_ms;

extern std::atomic_bool _running;

void monitor_children(pid_t parent_pid);
std::string iso_timestamp();
void log_audit_event(const std::string &log_message);