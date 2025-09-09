#include "GatewayListener.hpp"
#include "NetworkServer.hpp"
#include "Protocol.hpp"
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <chrono>

GatewayListener::GatewayListener(NetworkServer *owner, int port)
: sockfd_(-1), running_(false), owner_(owner), port_(port)
{
    sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ < 0) { perror("[GatewayListener] socket"); exit(1); }
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port_);
    server.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd_, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) { perror("[GatewayListener] bind"); close(sockfd_); exit(1); }
    int flags = fcntl(sockfd_, F_GETFL, 0);
    if (flags >= 0) fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);
}

GatewayListener::~GatewayListener() {
    stop();
}

void GatewayListener::start() {
    if (running_) return;
    running_ = true;
    std::thread([this]{ run(); }).detach();
}

void GatewayListener::stop() {
    if (!running_) return;
    running_ = false;
    if (sockfd_ >= 0) close(sockfd_);
    sockfd_ = -1;
}

void GatewayListener::run() {
    std::cout << "[GatewayListener] Listening on port " << port_ << std::endl;
    char buf[65536];
    while (running_) {
        sockaddr_in client{}; socklen_t sl = sizeof(client);
        ssize_t n = recvfrom(sockfd_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&client), &sl);
        if (n > 0) {
            UplinkItem it;
            it.data.assign((uint8_t*)buf, (uint8_t*)buf + n);
            it.addr = client;
            owner_->enqueueUplink(it);

            // immediate ACK depending on semtech identifier
            if (n >= 4) {
                uint8_t identifier = (uint8_t)buf[3];
                uint16_t token = ((uint8_t)buf[1] << 8) | (uint8_t)buf[2];
                if (identifier == PKT_PUSH_DATA) {
                    owner_->sendPushAck(token, client);
                } else if (identifier == PKT_PULL_DATA) {
                    owner_->sendPullAck(token, client);
                }
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    if (sockfd_ >= 0) close(sockfd_);
    sockfd_ = -1;
}
