#include "JoinServer.hpp"
#include "keyDeriver.hpp"
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

static void udpSendJson(const std::string &host, int port, const std::string &jsonStr) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    sendto(s, jsonStr.c_str(), jsonStr.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    close(s);
}

JoinServer::JoinServer(int port) : sockfd_(-1), port_(port) {
    sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ < 0) { perror("[JS] socket"); return; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port_); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { perror("[JS] bind"); close(sockfd_); sockfd_=-1; return; }
    std::cout << "[JS] listening on port " << port_ << std::endl;
}

JoinServer::~JoinServer() { if (sockfd_ >= 0) close(sockfd_); }

void JoinServer::start() {
    char buf[4096];
    while (true) {
        sockaddr_in client{}; socklen_t sl = sizeof(client);
        ssize_t n = recvfrom(sockfd_, buf, sizeof(buf)-1, 0, reinterpret_cast<sockaddr*>(&client), &sl);
        if (n <= 0) continue;
        buf[n] = '\0';
        cJSON *req = cJSON_Parse(buf);
        if (!req) continue;

        cJSON *reqfield = cJSON_GetObjectItem(req, "Req");
        std::string devEUIstr, appEUIstr, devNonceStr, appKeyStr = "DCC9BB50C0DB1FD7475DF9F128604F6F"; // example AppKey
        if (reqfield && cJSON_IsString(reqfield)) {
            cJSON *inner = cJSON_Parse(reqfield->valuestring);
            if (!inner) { cJSON_Delete(req); continue; }
            cJSON *devNonce = cJSON_GetObjectItem(inner, "DevNonce");
            cJSON *devEUI = cJSON_GetObjectItem(inner, "DevEUI");
            cJSON *appEUI = cJSON_GetObjectItem(inner, "AppEUI");
            if (devNonce && cJSON_IsString(devNonce)) devNonceStr = devNonce->valuestring;
            if (devEUI && cJSON_IsString(devEUI)) devEUIstr = devEUI->valuestring;
            if (appEUI && cJSON_IsString(appEUI)) appEUIstr = appEUI->valuestring;
            cJSON_Delete(inner);
        } else {
            cJSON *devNonce = cJSON_GetObjectItem(req, "DevNonce");
            if (devNonce && cJSON_IsString(devNonce)) devNonceStr = devNonce->valuestring;
        }

        if (devNonceStr.empty()) { cJSON_Delete(req); continue; }

        std::string joinB64, nwk, app, devaddr;
        bool ok = KeyDeriver::buildJoinAcceptAndKeys(appKeyStr, devNonceStr, joinB64, nwk, app, devaddr);
        cJSON *reply = cJSON_CreateObject();
        if (ok) {
            cJSON_AddStringToObject(reply, "JoinAccept", joinB64.c_str());
            cJSON_AddStringToObject(reply, "DevAddr", devaddr.c_str());
            char *repStr = cJSON_PrintUnformatted(reply);
            sendto(sockfd_, repStr, strlen(repStr), 0, reinterpret_cast<sockaddr*>(&client), sl);
            free(repStr);

            // push NwkSKey to NS (1702)
            cJSON *nsMsg = cJSON_CreateObject();
            cJSON_AddStringToObject(nsMsg, "Type", "NwkSKeyPush");
            cJSON_AddStringToObject(nsMsg, "DevAddr", devaddr.c_str());
            cJSON_AddStringToObject(nsMsg, "NwkSKey", nwk.c_str());
            char *nsStr = cJSON_PrintUnformatted(nsMsg);
            udpSendJson("127.0.0.1", 1702, nsStr);
            free(nsStr);
            cJSON_Delete(nsMsg);

            // push AppSKey to AS (1703)
            cJSON *asMsg = cJSON_CreateObject();
            cJSON_AddStringToObject(asMsg, "Type", "AppSKeyPush");
            cJSON_AddStringToObject(asMsg, "DevAddr", devaddr.c_str());
            cJSON_AddStringToObject(asMsg, "AppSKey", app.c_str());
            char *asStr = cJSON_PrintUnformatted(asMsg);
            udpSendJson("127.0.0.1", 1703, asStr);
            free(asStr);
            cJSON_Delete(asMsg);

            std::cout << "[JS] Join accept created for DevAddr=" << devaddr << std::endl;
        } else {
            cJSON_AddStringToObject(reply, "Error", "derive failed");
            char *repStr = cJSON_PrintUnformatted(reply);
            sendto(sockfd_, repStr, strlen(repStr), 0, reinterpret_cast<sockaddr*>(&client), sl);
            free(repStr);
        }
        cJSON_Delete(reply);
        cJSON_Delete(req);
    }
}
