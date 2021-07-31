#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t ihl_ : 4;
    uint8_t ver_ : 4;
    uint8_t tos_;
    uint16_t tl_;
    
    uint16_t idf_;
	uint16_t flgoff_;

    uint8_t ttl_;
    uint8_t ptl_;
    uint16_t chk_;

	Ip sip_;
	Ip dip_;

	uint8_t ver() { return ver_; }
	uint8_t ihl() { return ihl_; }
	uint8_t tos() { return tos_; }
    uint16_t tl() { return ntohs(tl_); }

	uint16_t idf() { return ntohs(idf_);}
	uint16_t flgoff() { return ntohs(flgoff_);}

	uint8_t ttl() { return ttl_;}
	uint8_t ptl() { return ptl_;}
	uint16_t chk() { return ntohs(chk_); }

	Ip sip() { return ntohl(sip_); }
	Ip dip() { return ntohl(dip_); }

	// protocol (ptl_)
    enum: uint8_t {
		ICMP = 1,
		IGMP = 2,
		TCP = 6,
		UDP = 17,
		ENCAP = 41,
		OSPF = 89,
		SCTP = 132
    };
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
