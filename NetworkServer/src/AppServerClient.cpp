#include "AppServerClient.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <cstring>

AppServerClient::AppServerClient(const std::string &host, int port)
: host_(host), port_(port), sock_(-1)
{
    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) { perror("[ASClient] socket"); sock_=-1; return; }
    memset(&asAddr_,0,sizeof(asAddr_));
    asAddr_.sin_family = AF_INET;
    asAddr_.sin_port = htons(port_);
    inet_pton(AF_INET, host_.c_str(), &asAddr_.sin_addr);
    int sz = 1<<20; setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
}

AppServerClient::~AppServerClient() { if (sock_>=0) close(sock_); }

void AppServerClient::forwardUplink(const std::string &devAddr, const std::string &payloadB64) {
    if (sock_ < 0) return;
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "Type", "UplinkData");
    cJSON_AddStringToObject(msg, "DevAddr", devAddr.c_str());
    cJSON_AddStringToObject(msg, "Payload", payloadB64.c_str());
    char *out = cJSON_PrintUnformatted(msg);
    if (out) {
        sendto(sock_, out, strlen(out), 0, reinterpret_cast<sockaddr*>(&asAddr_), sizeof(asAddr_));
        free(out);
    }
    cJSON_Delete(msg);
}
