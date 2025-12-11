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
Plugin sudo_audit /path/to/sudo_audit_plugin.so enable_stdout=true enable_syslog=true log_file=/tmp/sudo.log child_poll_ms=100 socket_path=/path/to/daemon.sock
```

All the following options are optional, but note that at least one logging method should be enabled:

* `enable_stdout`: if set to `true`, logs will be printed to stdout.
* `enable_syslog`: if set to `true`, logs will be sent to syslog.
* `log_file`: if set, logs will be appended to the specified file.
* `child_poll_ms`: interval in milliseconds to poll for child processes.
* `socket_path`: path to the Unix socket to send log messages to a logging daemon.

## Logging daemon

A simple logging daemon is provided in the `daemon/` directory. Compile it using:

```bash
g++ -g -std=c++17 -o sudo_audit_daemon daemon/audit_socket.cpp daemon/audit_daemon.cpp
```

To run the daemon, use:

```bash
./sudo_audit_daemon --socket /path/to/daemon.sock
```

The default value for `socket_path` is `/tmp/sudo_audit.sock`. Run `./sudo_audit_daemon --help` for more information.

If the daemon is running and the plugin is configured to use the `socket_path`, log messages will be sent to the daemon via a Unix domain socket.

The daemon runs in foreground and prints received log messages to stdout. You can redirect its output to a file if needed.
