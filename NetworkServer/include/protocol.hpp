#pragma once
#include <cstdint>

constexpr uint8_t PKT_PUSH_DATA  = 0x00;
constexpr uint8_t PKT_PUSH_ACK   = 0x01;
constexpr uint8_t PKT_PULL_DATA  = 0x02;
constexpr uint8_t PKT_PULL_RESP  = 0x03;
constexpr uint8_t PKT_PULL_ACK   = 0x04;
constexpr uint8_t PKT_TX_ACK     = 0x05;
