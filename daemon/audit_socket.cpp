#include <sys/socket.h>
#include <unistd.h>
#include <filesystem>
#include <iostream>

#include "audit_socket.hpp"

using namespace std;

Socket::Socket(string_view path) : _path(path) {
    init();
}

Socket::~Socket() {
    deinit();
}

void Socket::init(string_view path) {
    deinit();
    _path = path;
    init();
}

void Socket::init() {
    if (_path.empty()) {
        throw runtime_error("Socket path is empty");
    }

    try {
        filesystem::remove(_path);
    } catch (...) {
        // ignore
    }
    _socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (_socket_fd == -1) {
        throw runtime_error("Failed to create socket");
    }

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, _path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(_socket_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(_socket_fd);
        throw runtime_error("Failed to bind socket");
    }
}

ssize_t Socket::receive(char *buffer, size_t buffer_size) {
    return recvfrom(_socket_fd, buffer, buffer_size, 0, nullptr, nullptr);
}

void Socket::deinit() noexcept {
    if (_path.empty())
        return;
    cout << "Shutting down socket at " << _path << endl;
    if (_socket_fd != -1)
        close(_socket_fd);
    try {
        filesystem::remove(_path);
    } catch (...) {
        // ignore
    }
    _path = "";
}