#pragma once
#include <string>
#include <vector>
#include <cstdint>

class LoraPacket {
public:
    LoraPacket(const std::string &b64);
    bool valid() const { return parsed_; }
    bool isJoinRequest() const;
    bool isConfirmedUplink() const;
    std::string getDevEUIHex() const;
    std::string getAppEUIHex() const;
    std::string getDevAddrHex() const;
    std::string getDevNonceHex() const;
    uint32_t getFCnt() const;

private:
    bool parseBase64(const std::string &b64);
    void parseJoinRequest();
    void parseFHDR(); // parse devaddr/fcnt when possible

    std::vector<uint8_t> raw_;
    bool parsed_ = false;
    uint8_t devEUI_[8]{};
    uint8_t appEUI_[8]{};
    uint8_t devAddr_[4]{};
    uint8_t devNonce_[2]{};
    uint32_t fCnt_ = 0;
};
