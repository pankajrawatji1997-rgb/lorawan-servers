#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace LoraCrypto {
    std::vector<uint8_t> hexToBytes(const std::string &hex);
    std::string base64_encode(const std::vector<uint8_t> &data);
    // compute mic placeholder (real implementation would require aes/cmac)
    std::vector<uint8_t> computeMIC(const std::vector<uint8_t> &nwkSKey, const std::vector<uint8_t> &payload);
}
