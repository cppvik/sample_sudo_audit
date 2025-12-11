#pragma once

#include <string>
#include <sys/un.h>

#include <string_view>

class Socket {
public:
    Socket() = default;
    Socket(std::string_view path);
    ~Socket();
    void init(std::string_view path);
    void init();
    void deinit() noexcept;
    ssize_t receive(char *buffer, size_t buffer_size);
private:
    int _socket_fd;
    struct sockaddr_un addr;
    std::string _path;
};