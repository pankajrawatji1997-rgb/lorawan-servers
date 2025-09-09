#include "JoinServerClient.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cjson/cJSON.h>
#include <iostream>

JoinServerClient::JoinServerClient(const std::string &host, int port)
: host_(host), port_(port), sock_(-1)
{
    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) { perror("[JSClient] socket"); sock_ = -1; return; }
    memset(&jsAddr_, 0, sizeof(jsAddr_));
    jsAddr_.sin_family = AF_INET;
    jsAddr_.sin_port = htons(port_);
    inet_pton(AF_INET, host_.c_str(), &jsAddr_.sin_addr);
    int sz = 1<<20; setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
}

JoinServerClient::~JoinServerClient() {
    if (sock_>=0) close(sock_);
}

bool JoinServerClient::sendJoinRequest(const std::string &devEUI, const std::string &appEUI, const std::string &devNonce, uint32_t uplink_tmst, const struct sockaddr_in &gwAddr) {
    if (sock_ < 0) return false;
    // Build msg { Req: "<json>", UplinkTmst: N, GwAddr: "ip" }
    cJSON *inner = cJSON_CreateObject();
    cJSON_AddStringToObject(inner, "DevEUI", devEUI.c_str());
    cJSON_AddStringToObject(inner, "AppEUI", appEUI.c_str());
    cJSON_AddStringToObject(inner, "DevNonce", devNonce.c_str());
    // Note: AppKey not included here; NS may supply AppKey elsewhere; for demo we omit it
    char *inStr = cJSON_PrintUnformatted(inner);
    cJSON_Delete(inner);
    if (!inStr) return false;

    cJSON *pkg = cJSON_CreateObject();
    cJSON_AddStringToObject(pkg, "Req", inStr);
    cJSON_AddNumberToObject(pkg, "UplinkTmst", (double)uplink_tmst);
    char gwip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &gwAddr.sin_addr, gwip, sizeof(gwip));
    cJSON_AddStringToObject(pkg, "GwAddr", gwip);
    char *pkgStr = cJSON_PrintUnformatted(pkg);
    cJSON_Delete(pkg);
    free(inStr);
    if (!pkgStr) return false;
    ssize_t s = sendto(sock_, pkgStr, strlen(pkgStr), 0, reinterpret_cast<sockaddr*>(&jsAddr_), sizeof(jsAddr_));
    free(pkgStr);
    if (s<=0) return false;
    std::cout << "[JSClient] sent join req for " << devEUI << std::endl;
    return true;
}
