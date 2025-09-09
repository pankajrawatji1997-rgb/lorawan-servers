#pragma once
class AppServer {
public:
    AppServer(int port = 1703, int downlinkPort = 1704);
    ~AppServer();
    void start();
private:
    int sockfd_;
    int port_;
    int downlinkPort_;
};
