#pragma once
#include <string>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <unordered_map>
#include <cstdint>
#include <netinet/in.h>
struct UplinkItem {
    std::vector<uint8_t> data;
    struct sockaddr_in addr;
};

struct DownlinkItem {
    std::string b64;
    uint32_t tmst;
    bool isJoinAccept;
    struct sockaddr_in gwAddr;
};

class GatewayListener;
class JoinServerClient;
class AppServerClient;
class LoraPacket;

class NetworkServer {
public:
    NetworkServer();
    ~NetworkServer();
    void start();
    void stop();

    // GatewayListener calls this
    void enqueueUplink(const UplinkItem &it);

    // Called by helpers to push a downlink to queue (Join accept or App requested)
    void pushDownlink(const DownlinkItem &dl);

    // Called by GatewayListener when ACK required immediately
    void sendPushAck(uint16_t token, const struct sockaddr_in &addr);
    void sendPullAck(uint16_t token, const struct sockaddr_in &addr);

    // Key storage from JS or other control sockets
    void storeNwkSKey(const std::string &devAddr, const std::string &nwkSKey);
    void storeAppSKey(const std::string &devAddr, const std::string &appSKey);

private:
    void workerLoop();
    void txLoop();
    void jsControlLoop();    // listens for NwkSKeyPush/JoinAccept etc (port 1702)
    void asDownlinkLoop();   // listens for DownlinkReq from AS (port 1704)
    void processPacket(const UplinkItem &it);

    void sendSemtechPkt(uint8_t identifier, uint16_t token,
                        const struct sockaddr_in &addr,
                        const void *payload = nullptr, size_t len = 0);
    void sendPullResp(const struct sockaddr_in &addr, const std::string &b64, uint32_t tmst, bool isJoin);

    GatewayListener *gwListener_;
    JoinServerClient *jsClient_;
    AppServerClient *asClient_;

    int sockfd_;

    // background processing queue
    std::mutex qMutex_;
    std::condition_variable qCv_;
    std::queue<UplinkItem> uplinkQ_;

    std::mutex dlMutex_;
    std::queue<DownlinkItem> dlQ_;

    // sessions: DevAddr hex -> keys and counters
    struct DeviceContext {
        std::string nwkSKey;
        std::string appSKey;
        uint32_t fCntUp = 0;
        uint32_t fCntDown = 0;
    };
    std::mutex ctxMutex_;
    std::unordered_map<std::string, DeviceContext> devices_;

    bool running_;
    std::thread workerThread_;
    std::thread txThread_;
    std::thread jsControlThread_;
    std::thread asDownlinkThread_;
};
