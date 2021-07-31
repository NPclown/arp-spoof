#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct IcmpHdr final {
    uint8_t type_;
    uint8_t code_;
    uint16_t chk_;
	uint32_t roh_[3];
    
	uint8_t type() { return type_; }
	uint8_t code() { return code_; }
    uint16_t chk() { return ntohs(chk_); }
	uint32_t roh() { return roh_[1]; }

    enum: uint8_t {
		ECHO_REPLAY = 0,
		ECHO_REQUEST = 8
    };
};
typedef IcmpHdr *PIcmpHdr;
#pragma pack(pop)
