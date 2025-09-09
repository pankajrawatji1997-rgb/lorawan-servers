#include "LoraCrypto.hpp"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>
#include <vector>
#include <sstream>

namespace LoraCrypto {

std::vector<uint8_t> hexToBytes(const std::string &hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2) return out;
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int v = 0;
        sscanf(hex.substr(i,2).c_str(), "%02x", &v);
        out.push_back((uint8_t)v);
    }
    return out;
}

std::string base64_encode(const std::vector<uint8_t> &data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data.data(), (int)data.size());
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}

// simple placeholder: returns 4-byte vector (not a real MIC)
std::vector<uint8_t> computeMIC(const std::vector<uint8_t> &nwkSKey, const std::vector<uint8_t> &payload) {
    (void)nwkSKey;
    std::vector<uint8_t> mic(4, 0);
    uint32_t acc = 0;
    for (auto b : payload) acc += b;
    mic[0] = acc & 0xFF; mic[1] = (acc>>8)&0xFF; mic[2] = (acc>>16)&0xFF; mic[3] = (acc>>24)&0xFF;
    return mic;
}

} // namespace
