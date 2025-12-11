build:
	g++ -g -fPIC -shared -std=c++17 -o sudo_audit_plugin.so plugin/sudo_audit.cpp plugin/audit_helpers.cpp -lpthread
	g++ -g -std=c++17 -o sudo_audit_daemon daemon/audit_socket.cpp daemon/audit_daemon.cpp