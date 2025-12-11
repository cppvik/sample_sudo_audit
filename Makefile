build:
	g++ -fPIC -shared -std=c++17 -o sudo_audit_plugin.so sudo_audit.cpp audit_helpers.cpp  -lpthread