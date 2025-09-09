#include "AppServer.hpp"
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <openssl/evp.h>
#include <openssl/buffer.h>

static void udpSendJson(const std::string &host, int port, const std::string &jsonStr) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    sendto(s, jsonStr.c_str(), jsonStr.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    close(s);
}

static std::vector<uint8_t> hexToBytes(const std::string &hex) {
    std::vector<uint8_t> out;
    if (hex.size()%2) return out;
    for (size_t i=0;i<hex.size(); i+=2) {
        unsigned int v; sscanf(hex.substr(i,2).c_str(), "%02x", &v);
        out.push_back((uint8_t)v);
    }
    return out;
}

static std::vector<uint8_t> aes128_block_encrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &block) {
    std::vector<uint8_t> out(16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx,0);
    EVP_EncryptUpdate(ctx, out.data(), &outlen, block.data(), 16);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

static std::vector<uint8_t> lorawan_cipher(const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &devAddr,
                                           uint32_t fCnt,
                                           bool downlink,
                                           const std::vector<uint8_t> &data) {
    std::vector<uint8_t> out(data.size());
    size_t nBlocks = (data.size() + 15) / 16;
    size_t off = 0;
    for (size_t i = 1; i <= nBlocks; i++) {
        uint8_t a[16] = {0};
        a[0] = 0x01;
        a[5] = downlink ? 0x01 : 0x00;
        for (int j = 0; j < 4; j++) a[6 + j] = (j < (int)devAddr.size()) ? devAddr[j] : 0;
        a[10] = fCnt & 0xFF;
        a[11] = (fCnt >> 8) & 0xFF;
        a[12] = (fCnt >> 16) & 0xFF;
        a[13] = (fCnt >> 24) & 0xFF;
        a[15] = i;
        std::vector<uint8_t> S = aes128_block_encrypt(key, std::vector<uint8_t>(a, a+16));
        size_t blk = std::min((size_t)16, data.size() - off);
        for (size_t j = 0; j < blk; j++) out[off + j] = data[off + j] ^ S[j];
        off += blk;
    }
    return out;
}

AppServer::AppServer(int port, int downlinkPort): sockfd_(-1), port_(port), downlinkPort_(downlinkPort) {
    sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ < 0) { perror("[AS] socket"); return; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port_); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { perror("[AS] bind"); close(sockfd_); sockfd_=-1; return; }
    std::cout << "[AS] listening on " << port_ << std::endl;
}

AppServer::~AppServer() { if (sockfd_ >= 0) close(sockfd_); }

void AppServer::start() {
    std::unordered_map<std::string, std::string> appKeys;
    char buf[4096];
    while (true) {
        sockaddr_in client{}; socklen_t sl = sizeof(client);
        ssize_t n = recvfrom(sockfd_, buf, sizeof(buf)-1, 0, reinterpret_cast<sockaddr*>(&client), &sl);
        if (n <= 0) continue;
        buf[n] = '\0';
        cJSON *root = cJSON_Parse(buf);
        if (!root) continue;
        cJSON *type = cJSON_GetObjectItem(root, "Type");
        if (type && cJSON_IsString(type) && std::string(type->valuestring) == "AppSKeyPush") {
            cJSON *devAddr = cJSON_GetObjectItem(root, "DevAddr");
            cJSON *key = cJSON_GetObjectItem(root, "AppSKey");
            if (devAddr && key) {
                appKeys[devAddr->valuestring] = key->valuestring;
                std::cout << "[AS] stored AppSKey for " << devAddr->valuestring << std::endl;
            }
        } else if (type && cJSON_IsString(type) && std::string(type->valuestring) == "UplinkData") {
            cJSON *devAddr = cJSON_GetObjectItem(root, "DevAddr");
            cJSON *payload = cJSON_GetObjectItem(root, "Payload");
            if (devAddr && payload) {
                std::string da = devAddr->valuestring;
                std::string payloadB64 = payload->valuestring;
                std::cout << "[AS] Uplink for " << da << " payload(b64): " << payloadB64 << std::endl;
                // decrypting the app payload would normally occur here using AppSKey. For demo we simply respond with an "OK" downlink:
                std::string appS = appKeys.count(da) ? appKeys[da] : "";
                std::string downB64 = "";
                if (!appS.empty()) {
                    std::vector<uint8_t> key = hexToBytes(appS);
                    std::vector<uint8_t> dev = hexToBytes(da);
                    std::vector<uint8_t> plain = {'O', 'K'}; // sample
                    auto enc = lorawan_cipher(key, dev, 1, true, plain);
                    BIO *b64 = BIO_new(BIO_f_base64()); BIO *mem = BIO_new(BIO_s_mem()); BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); BIO_push(b64, mem);
                    BIO_write(b64, enc.data(), enc.size()); BIO_flush(b64); BUF_MEM *bptr; BIO_get_mem_ptr(b64, &bptr);
                    downB64.assign(bptr->data, bptr->length);
                    BIO_free_all(b64);
                }
                // Build DownlinkReq and send to NS on port 1704
                cJSON *dl = cJSON_CreateObject();
                cJSON_AddStringToObject(dl, "Type", "DownlinkReq");
                cJSON_AddStringToObject(dl, "DevAddr", da.c_str());
                cJSON_AddStringToObject(dl, "Payload", downB64.c_str());
                char *out = cJSON_PrintUnformatted(dl);
                if (out) {
                    udpSendJson("127.0.0.1", downlinkPort_, out);
                    free(out);
                }
                cJSON_Delete(dl);
                std::cout << "[AS] Sent DownlinkReq for " << da << std::endl;
            }
        }
        cJSON_Delete(root);
    }
}
