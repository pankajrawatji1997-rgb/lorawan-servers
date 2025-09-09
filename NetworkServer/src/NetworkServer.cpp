#include "NetworkServer.hpp"
#include "GatewayListener.hpp"
#include "JoinServerClient.hpp"
#include "AppServerClient.hpp"
#include "LoraPacket.hpp"
#include "LoraCrypto.hpp"
#include "protocol.hpp"
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>

NetworkServer::NetworkServer()
: gwListener_(nullptr), jsClient_(nullptr), asClient_(nullptr), sockfd_(-1), running_(false)
{
    gwListener_ = new GatewayListener(this, 1700);
    jsClient_ = new JoinServerClient("127.0.0.1", 1701);
    asClient_ = new AppServerClient("127.0.0.1", 1703);

    sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ < 0) { perror("[NS] socket"); exit(1); }
    // bind a control port for receiving key pushes and downlink requests
    // sockaddr_in ctrl{}; ctrl.sin_family = AF_INET; ctrl.sin_port = htons(1702); ctrl.sin_addr.s_addr = INADDR_ANY;
    // if (bind(sockfd_, reinterpret_cast<sockaddr*>(&ctrl), sizeof(ctrl)) < 0) {
    //     // non-fatal: other processes might bind - we'll still use sockfd for sendto
    //     perror("[NS] bind control 1702 (continuing)");
    // }
}

NetworkServer::~NetworkServer() {
    stop();
    delete gwListener_;
    delete jsClient_;
    delete asClient_;
    if (sockfd_ >= 0) close(sockfd_);
}

void NetworkServer::start() {
    if (running_) return;
    running_ = true;
    gwListener_->start();
    workerThread_ = std::thread(&NetworkServer::workerLoop, this);
    txThread_ = std::thread(&NetworkServer::txLoop, this);
    jsControlThread_ = std::thread(&NetworkServer::jsControlLoop, this);
    asDownlinkThread_ = std::thread(&NetworkServer::asDownlinkLoop, this);
    std::cout << "[NS] started\n";
}

void NetworkServer::stop() {
    running_ = false;
    if (gwListener_) gwListener_->stop();
    qCv_.notify_all();
    if (workerThread_.joinable()) workerThread_.join();
    if (txThread_.joinable()) txThread_.join();
    if (jsControlThread_.joinable()) jsControlThread_.join();
    if (asDownlinkThread_.joinable()) asDownlinkThread_.join();
}

void NetworkServer::enqueueUplink(const UplinkItem &it) {
    {
        std::lock_guard<std::mutex> lk(qMutex_);
        uplinkQ_.push(it);
    }
    qCv_.notify_one();
}

void NetworkServer::pushDownlink(const DownlinkItem &dl) {
    std::lock_guard<std::mutex> lk(dlMutex_);
    dlQ_.push(dl);
}

void NetworkServer::workerLoop() {
    std::cout << "WorkerThread started\n";
    while (running_) {
        UplinkItem it;
        {
            std::unique_lock<std::mutex> lk(qMutex_);
            qCv_.wait(lk, [&]{ return !uplinkQ_.empty() || !running_; });
            if (!running_) break;
            it = std::move(uplinkQ_.front());
            uplinkQ_.pop();
        }
        processPacket(it);
    }
}

void NetworkServer::processPacket(const UplinkItem &it) {
    const char* data = reinterpret_cast<const char*>(it.data.data());
    int len = (int)it.data.size();
    if (len < 4) return;
    uint16_t token = (static_cast<uint8_t>(data[1]) << 8) | static_cast<uint8_t>(data[2]);
    uint8_t id = static_cast<uint8_t>(data[3]);

    if (id == PKT_PUSH_DATA) {
        if (len <= 12) return;
        std::string jsonStr(data + 12, static_cast<size_t>(len - 12));
        cJSON *root = cJSON_Parse(jsonStr.c_str());
        if (!root) return;
        cJSON *rxpk = cJSON_GetObjectItem(root, "rxpk");
        if (rxpk && cJSON_IsArray(rxpk)) {
            int n = cJSON_GetArraySize(rxpk);
            for (int i=0;i<n;i++) {
                cJSON *item = cJSON_GetArrayItem(rxpk, i);
                cJSON *tmst = cJSON_GetObjectItem(item, "tmst");
                cJSON *dataItem = cJSON_GetObjectItem(item, "data");
                if (!tmst || !dataItem) continue;
                uint32_t uplink_tmst = (uint32_t)tmst->valuedouble;
                std::string b64 = dataItem->valuestring;
                LoraPacket pkt(b64);
                if (pkt.valid() && pkt.isJoinRequest()) {
                    // send join req to join server (fire-and-forget)
                    jsClient_->sendJoinRequest(pkt.getDevEUIHex(), pkt.getAppEUIHex(), pkt.getDevNonceHex(), uplink_tmst, it.addr);
                } else if (pkt.valid()) {
                    // normal uplink: forward to AS and update fCntUp
                    std::string devAddr = pkt.getDevAddrHex();
                    {
                        std::lock_guard<std::mutex> lk(ctxMutex_);
                        auto &ctx = devices_[devAddr];
                        ctx.fCntUp++;
                        // if confirmed uplink, prepare ack downlink
                        // here we assume some confirmed detection; for demo we prepare an ack when requested
                        if (pkt.isConfirmedUplink()) {
                            // prepare an empty ACK downlink PHYPayload (simplified) using nwkSKey
                            std::string nwk = ctx.nwkSKey;
                            // create minimal PHYPayload (MHDR + FHDR + MIC) - here we return placeholder
                            std::vector<uint8_t> phy = {0xA0, 0x00}; // placeholder
                            std::string b64 = LoraCrypto::base64_encode(phy);
                            DownlinkItem dl;
                            dl.b64 = b64;
                            dl.tmst = pkt.getFCnt(); // using pkt tmst placeholder
                            dl.isJoinAccept = false;
                            dl.gwAddr = it.addr;
                            pushDownlink(dl);
                            ctx.fCntDown++;
                        }
                    }
                    // forward to AS
                    asClient_->forwardUplink(devAddr, b64);
                }
            }
        }
        cJSON_Delete(root);
    } else if (id == PKT_PULL_DATA) {
        // When gateway polls for downlink (PULL_DATA), NS should already have sent a PULL_ACK from listener.
        // Here we check pending downlinks and respond with PULL_RESP if present.
        std::lock_guard<std::mutex> lk(dlMutex_);
        if (!dlQ_.empty()) {
            DownlinkItem dl = dlQ_.front(); dlQ_.pop();
            sendPullResp(it.addr, dl.b64, dl.tmst, dl.isJoinAccept);
        }
    } else if (id == PKT_TX_ACK) {
        std::cout << "[NS] TX_ACK received\n";
    }
}

void NetworkServer::txLoop() {
    while (running_) {
        // For now, tx loop simply sleeps. Could be extended for timed events.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void NetworkServer::sendSemtechPkt(uint8_t identifier, uint16_t token,
                        const struct sockaddr_in &addr,
                        const void *payload, size_t len) {
    uint8_t hdr[12];
    hdr[0]=0x02; hdr[1]=(token>>8)&0xFF; hdr[2]=token&0xFF; hdr[3]=identifier;
    memset(hdr+4,0,8);
    std::vector<uint8_t> pkt;
    pkt.insert(pkt.end(), hdr, hdr+12);
    if (payload && len>0) pkt.insert(pkt.end(), (const uint8_t*)payload, (const uint8_t*)payload + len);
    sendto(sockfd_, pkt.data(), pkt.size(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
}

void NetworkServer::sendPushAck(uint16_t token, const struct sockaddr_in &addr) {
    sendSemtechPkt(PKT_PUSH_ACK, token, addr, nullptr, 0);
}

void NetworkServer::sendPullAck(uint16_t token, const struct sockaddr_in &addr) {
    sendSemtechPkt(PKT_PULL_ACK, token, addr, nullptr, 0);
}

void NetworkServer::sendPullResp(const struct sockaddr_in &addr, const std::string &b64, uint32_t tmst, bool isJoin) {
    cJSON *txpk = cJSON_CreateObject();
    // schedule RX1 at uplink_tmst + 1s (1e6 us)
    cJSON_AddNumberToObject(txpk, "tmst", (double)(tmst + 1000000));
    cJSON_AddNumberToObject(txpk, "freq", 869.525);
    cJSON_AddNumberToObject(txpk, "rfch", 0);
    cJSON_AddNumberToObject(txpk, "powe", 14);
    cJSON_AddStringToObject(txpk, "modu", "LORA");
    cJSON_AddStringToObject(txpk, "datr", "SF12BW125");
    cJSON_AddStringToObject(txpk, "codr", "4/5");
    cJSON_AddBoolToObject(txpk, "ipol", true);
    cJSON_AddStringToObject(txpk, "data", b64.c_str());
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "txpk", txpk);
    char *out = cJSON_PrintUnformatted(root);
    if (out) {
        sendSemtechPkt(PKT_PULL_RESP, 0x0000, addr, out, strlen(out));
        free(out);
        std::cout << "[NS] Sent PULL_RESP\n";
    }
    cJSON_Delete(root);
}

void NetworkServer::storeNwkSKey(const std::string &devAddr, const std::string &nwkSKey) {
    std::lock_guard<std::mutex> lk(ctxMutex_);
    devices_[devAddr].nwkSKey = nwkSKey;
    std::cout << "[NS] stored NwkSKey for " << devAddr << "\n";
}

void NetworkServer::storeAppSKey(const std::string &devAddr, const std::string &appSKey) {
    std::lock_guard<std::mutex> lk(ctxMutex_);
    devices_[devAddr].appSKey = appSKey;
    std::cout << "[NS] stored AppSKey for " << devAddr << "\n";
}

// listens for JS pushes (NwkSKeyPush) and JoinAccept replies on port 1702
void NetworkServer::jsControlLoop() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("[NS ctrl] socket"); return; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(1702); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { perror("[NS ctrl] bind"); /*continue but still listen on s*/ }
    char buf[4096];
    while (running_) {
        sockaddr_in client{}; socklen_t sl = sizeof(client);
        ssize_t n = recvfrom(s, buf, sizeof(buf)-1, 0, reinterpret_cast<sockaddr*>(&client), &sl);
        if (n <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
        buf[n] = '\0';
        cJSON *root = cJSON_Parse(buf);
        if (!root) continue;
        cJSON *type = cJSON_GetObjectItem(root, "Type");
        if (type && cJSON_IsString(type)) {
            std::string t = type->valuestring;
            if (t == "NwkSKeyPush") {
                cJSON *devAddr = cJSON_GetObjectItem(root, "DevAddr");
                cJSON *nwk = cJSON_GetObjectItem(root, "NwkSKey");
                if (devAddr && nwk) storeNwkSKey(devAddr->valuestring, nwk->valuestring);
            } else if (t == "AppSKeyPush") {
                cJSON *devAddr = cJSON_GetObjectItem(root, "DevAddr");
                cJSON *app = cJSON_GetObjectItem(root, "AppSKey");
                if (devAddr && app) storeAppSKey(devAddr->valuestring, app->valuestring);
            }
        } else {
            // maybe it's JoinAccept reply with JoinAccept JSON { "JoinAccept":"<b64>", "DevAddr":".."}
            cJSON *ja = cJSON_GetObjectItem(root, "JoinAccept");
            cJSON *devAddr = cJSON_GetObjectItem(root, "DevAddr");
            if (ja && devAddr) {
                std::string dev = devAddr->valuestring;
                std::string joinB64 = ja->valuestring;
                // push immediate downlink: we don't have gwAddr here; use recv source for demo
                DownlinkItem dl;
                dl.b64 = joinB64;
                dl.tmst = 0; // NS will send at immediacy offset in sendPullResp
                dl.isJoinAccept = true;
                dl.gwAddr = client; // reply to sender gateway if known
                pushDownlink(dl);
                std::cout << "[NS] queued JoinAccept downlink for " << dev << std::endl;
            }
        }
        cJSON_Delete(root);
    }
    close(s);
}

// listens for DownlinkReq from AS on port 1704
void NetworkServer::asDownlinkLoop() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("[NS asdl] socket"); return; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(1704); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { perror("[NS asdl] bind"); }
    char buf[4096];
    while (running_) {
        sockaddr_in client{}; socklen_t sl = sizeof(client);
        ssize_t n = recvfrom(s, buf, sizeof(buf)-1, 0, reinterpret_cast<sockaddr*>(&client), &sl);
        if (n <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
        buf[n] = '\0';
        cJSON *root = cJSON_Parse(buf);
        if (!root) continue;
        cJSON *type = cJSON_GetObjectItem(root, "Type");
        if (type && cJSON_IsString(type) && std::string(type->valuestring) == "DownlinkReq") {
            cJSON *devAddr = cJSON_GetObjectItem(root, "DevAddr");
            cJSON *payload = cJSON_GetObjectItem(root, "Payload");
            if (devAddr && payload) {
                DownlinkItem dl;
                dl.b64 = payload->valuestring;
                dl.tmst = 0;
                dl.isJoinAccept = false;
                // For demo, send to any gateway (choose loopback)
                sockaddr_in gw{}; gw.sin_family = AF_INET; gw.sin_port = htons(1700); inet_pton(AF_INET, "127.0.0.1", &gw.sin_addr);
                dl.gwAddr = gw;
                pushDownlink(dl);
                std::cout << "[NS] queued Downlink from AS for " << devAddr->valuestring << std::endl;
            }
        }
        cJSON_Delete(root);
    }
    close(s);
}
