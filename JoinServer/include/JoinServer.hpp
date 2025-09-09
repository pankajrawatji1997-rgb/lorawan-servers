#pragma once
class JoinServer {
public:
    JoinServer(int port = 1701);
    ~JoinServer();
    void start();
private:
    int sockfd_;
    int port_;
};
