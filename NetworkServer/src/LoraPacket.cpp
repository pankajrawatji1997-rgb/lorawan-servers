#include "LoraPacket.hpp"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <cstring>
#include <sstream>
#include <iomanip>

static std::string bytesHex(const uint8_t *b, size_t len) {
    std::ostringstream ss; ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i=0;i<len;i++) ss << std::setw(2) << (int)b[i];
    return ss.str();
}

LoraPacket::LoraPacket(const std::string &b64) {
    parsed_ = parseBase64(b64);
    if (!parsed_) return;
    if (isJoinRequest()) parseJoinRequest();
    else parseFHDR();
}

bool LoraPacket::parseBase64(const std::string &b64) {
    BIO *b64b = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(b64.data(), (int)b64.size());
    BIO_set_flags(b64b, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64b, mem);
    int maxlen = (int)((b64.size()*3)/4 + 16);
    raw_.resize(maxlen);
    int r = BIO_read(b64b, raw_.data(), maxlen);
    BIO_free_all(b64b);
    if (r <= 0) return false;
    raw_.resize(r);
    parsed_ = true;
    return true;
}

bool LoraPacket::isJoinRequest() const {
    if (!parsed_ || raw_.empty()) return false;
    uint8_t mhdr = raw_[0];
    uint8_t mtype = (mhdr >> 5) & 0x07;
    return mtype == 0x00;
}

// rough heuristic for confirmed uplink: FHDR FCtrl's ACK bit set? For uplink, FCtrl bit 5 (ACK) isn't applicable.
// We'll detect confirmed uplink by MHDR type Data (0x02) and FCtrl's bit 0x20 meaning ADR? This is heuristic and may need real MAC parsing.
bool LoraPacket::isConfirmedUplink() const {
    if (!parsed_ || raw_.size() < 8) return false;
    uint8_t mhdr = raw_[0];
    uint8_t mtype = (mhdr >> 5) & 0x07;
    // 0x02 = unconfirmed data up, 0x03 = confirmed data up (for LoRaWAN 1.0)
    return (mtype == 0x02 || mtype == 0x03) && ( (mhdr >> 5) & 0x07 ) == 0x02;
}

void LoraPacket::parseJoinRequest() {
    // MHDR(1) + AppEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4) minimum 23 bytes
    if (raw_.size() < 23) return;
    // AppEUI little-endian in message
    for (int i=0;i<8;i++) appEUI_[i] = raw_[1 + (7 - i)];
    for (int i=0;i<8;i++) devEUI_[i] = raw_[9 + (7 - i)];
    // DevNonce is 2 bytes at offset 17 (little-endian)
    devNonce_[0] = raw_[17];
    devNonce_[1] = raw_[16];
}

void LoraPacket::parseFHDR() {
    // Attempt to extract DevAddr and FCnt from PHY payload
    // MAC PHYPayload format: MHDR(1) | MACPayload | MIC(4)
    // MACPayload for data up: FHDR(DevAddr(4) | FCtrl(1) | FCnt(2) | FOpts...) | FPort(1) | FRMPayload...
    // DevAddr typically appears at offset 1..4 (little-endian).
    if (raw_.size() < 8) return;
    // naive: bytes 1..4 might be DevAddr in little-endian
    for (int i=0;i<4;i++) devAddr_[i] = raw_[1 + i];
    // attempt FCnt from bytes 6..7 (little-endian) — approximate
    if (raw_.size() >= 8) {
        uint16_t fcnt = (uint8_t)raw_[6] | ((uint8_t)raw_[7] << 8);
        fCnt_ = fcnt;
    }
}

std::string LoraPacket::getDevEUIHex() const { return bytesHex(devEUI_, 8); }
std::string LoraPacket::getAppEUIHex() const { return bytesHex(appEUI_, 8); }
std::string LoraPacket::getDevAddrHex() const { return bytesHex(devAddr_, 4); }
std::string LoraPacket::getDevNonceHex() const { return bytesHex(devNonce_, 2); }
uint32_t LoraPacket::getFCnt() const { return fCnt_; }
