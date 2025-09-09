#pragma once
#include <string>

class KeyDeriver {
public:
    static bool buildJoinAcceptAndKeys(const std::string &appKeyHex,
                                       const std::string &devNonceHex,
                                       std::string &joinAcceptB64,
                                       std::string &nwkSKeyHex,
                                       std::string &appSKeyHex,
                                       std::string &devAddrHex);
};
