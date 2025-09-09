#include "KeyDeriver.hpp"
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <vector>

static bool hexToBytes(const std::string &hex, std::vector<uint8_t> &out) {
    out.clear();
    if (hex.size() % 2) return false;
    for (size_t i=0;i<hex.size(); i+=2) {
        unsigned int v; if (sscanf(hex.substr(i,2).c_str(), "%02x", &v) != 1) return false;
        out.push_back((uint8_t)v);
    }
    return true;
}
static std::string bytesToHex(const uint8_t *b, size_t len) {
    std::ostringstream ss; ss << std::uppercase << std::hex << std::setfill('0');
    for (size_t i=0;i<len;i++) ss << std::setw(2) << (int)b[i];
    return ss.str();
}
static std::string base64Encode(const uint8_t *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64()); BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); BIO_push(b64, mem);
    BIO_write(b64, data, (int)len); BIO_flush(b64);
    BUF_MEM *bptr; BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length); BIO_free_all(b64);
    return out;
}
static void randomBytes(uint8_t *buf, size_t len) {
    static std::random_device rd; static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> d(0,255);
    for (size_t i=0;i<len;i++) buf[i] = (uint8_t)d(gen);
}

static bool aes128_ecb_encrypt(const uint8_t key[16], const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    out.assign(in.size(), 0);
    int outlen = 0;
    if (1 != EVP_EncryptUpdate(ctx, out.data(), &outlen, in.data(), (int)in.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
static bool aes128_ecb_decrypt(const uint8_t key[16], const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    out.assign(in.size(), 0);
    int outlen = 0;
    if (1 != EVP_DecryptUpdate(ctx, out.data(), &outlen, in.data(), (int)in.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
static bool aes_cmac(const uint8_t key[16], const uint8_t *data, size_t len, uint8_t out[16]) {
    CMAC_CTX *ctx = CMAC_CTX_new(); if (!ctx) return false;
    size_t maclen = 0;
    if (1 != CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), nullptr)) { CMAC_CTX_free(ctx); return false; }
    if (1 != CMAC_Update(ctx, data, len)) { CMAC_CTX_free(ctx); return false; }
    if (1 != CMAC_Final(ctx, out, &maclen)) { CMAC_CTX_free(ctx); return false; }
    CMAC_CTX_free(ctx); return (maclen > 0);
}

bool KeyDeriver::buildJoinAcceptAndKeys(const std::string &appKeyHex,
                                        const std::string &devNonceHex,
                                        std::string &joinAcceptB64,
                                        std::string &nwkSKeyHex,
                                        std::string &appSKeyHex,
                                        std::string &devAddrHex)
{
    std::vector<uint8_t> appKey;
    if (!hexToBytes(appKeyHex, appKey) || appKey.size() != 16) return false;
    std::vector<uint8_t> devNonce;
    if (!hexToBytes(devNonceHex, devNonce) || devNonce.size() != 2) return false;

    uint8_t appNonce[3], netID[3], devAddr[4];
    randomBytes(appNonce, 3);
    randomBytes(netID, 3);
    randomBytes(devAddr, 4);

    std::vector<uint8_t> jaPlain;
    jaPlain.insert(jaPlain.end(), appNonce, appNonce+3);
    jaPlain.insert(jaPlain.end(), netID, netID+3);
    jaPlain.insert(jaPlain.end(), devAddr, devAddr+4);
    jaPlain.push_back(0x00);
    jaPlain.push_back(0x01);

    uint8_t MHDR = 0x20;
    std::vector<uint8_t> micInput;
    micInput.push_back(MHDR);
    micInput.insert(micInput.end(), jaPlain.begin(), jaPlain.end());

    uint8_t micFull[16];
    if (!aes_cmac(appKey.data(), micInput.data(), micInput.size(), micFull)) return false;
    uint8_t mic4[4]; memcpy(mic4, micFull, 4);

    std::vector<uint8_t> toEncrypt = jaPlain;
    toEncrypt.insert(toEncrypt.end(), mic4, mic4+4);
    if (toEncrypt.size() % 16) toEncrypt.resize(((toEncrypt.size()/16)+1)*16, 0);

    std::vector<uint8_t> encrypted;
    if (!aes128_ecb_decrypt(appKey.data(), toEncrypt, encrypted)) return false;

    std::vector<uint8_t> phy;
    phy.push_back(MHDR);
    phy.insert(phy.end(), encrypted.begin(), encrypted.end());

    joinAcceptB64 = base64Encode(phy.data(), phy.size());

    uint8_t derive[16];
    derive[0] = 0x01;
    memcpy(derive+1, appNonce, 3);
    memcpy(derive+4, netID, 3);
    memcpy(derive+7, devNonce.data(), 2);
    memset(derive+9, 0, 7);
    std::vector<uint8_t> out;
    if (!aes128_ecb_encrypt(appKey.data(), std::vector<uint8_t>(derive, derive+16), out) || out.size() != 16) return false;
    nwkSKeyHex = bytesToHex(out.data(), 16);
    derive[0] = 0x02;
    if (!aes128_ecb_encrypt(appKey.data(), std::vector<uint8_t>(derive, derive+16), out) || out.size() != 16) return false;
    appSKeyHex = bytesToHex(out.data(), 16);
    devAddrHex = bytesToHex(devAddr, 4);
    return true;
}
