# Simple Sudo Audit Plugin in C++

This is a simple sudo audit plugin written in C++. It logs executed commands to a specified log file / syslog / stdout.

## Compilation

To compile the plugin, use the following command:

```bash
g++ -fPIC -shared -std=c++17 -o sudo_audit_plugin.so sudo_audit.cpp audit_helpers.cpp  -lpthread
```

## Configuration

To use the plugin, add the following line to your `/etc/sudo.conf` file:

```conf
Plugin sudo_audit /path/to/sudo_audit_plugin.so enable_stdout=true enable_syslog=true log_file=/tmp/sudo.log child_poll_ms=100
```

Note the used options:

* `enable_stdout`: if set to `true`, logs will be printed to stdout.
* `enable_syslog`: if set to `true`, logs will be sent to syslog.
* `log_file`: if set, logs will be appended to the specified file.
* `child_poll_ms`: interval in milliseconds to poll for child processes.
