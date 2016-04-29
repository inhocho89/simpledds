#ifndef __PACKET_H__
#define __PACKET_H__
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstdlib>

#define ETH_OFFSET 14

class Packet {
private:
	uint8_t *packet_;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;	
public:
	Packet() : packet_(0) { }
	Packet(uint8_t *packet) : packet_(packet) {
		unsigned int iph_size;
		packet_ = packet;
		iph = (struct iphdr *)(packet+ETH_OFFSET);
		iph_size = (unsigned int)iph->ihl*4;
		tcph = NULL;
		udph = NULL;
		if (iph->protocol == IPPROTO_TCP)
			tcph = (struct tcphdr *)(packet+ETH_OFFSET+iph_size);
		else if (iph->protocol == IPPROTO_UDP)
			udph = (struct udphdr *)(packet+ETH_OFFSET+iph_size);
	}

	uint16_t eth_length () {return ntohs(iph->tot_len)+ETH_OFFSET;}	
	uint32_t ip_saddr () {return iph->saddr;}
	uint32_t ip_daddr () {return iph->daddr;}	
	uint8_t ip_protocol () {return iph->protocol;}
	bool is_TCP () {return (iph->protocol == IPPROTO_TCP);}
	bool is_UDP () {return (iph->protocol == IPPROTO_UDP);}
	uint16_t sport ();
	uint16_t dport ();
	uint32_t tcp_seqN () {return is_TCP()?ntohl(tcph->seq):0;}
	uint32_t tcp_ackN () {return is_TCP()?ntohl(tcph->ack_seq):0;}
	bool tcp_syn () {return is_TCP()?(bool)tcph->syn:false;}
	bool tcp_ack () {return is_TCP()?(bool)tcph->ack:false;}
	bool tcp_fin () {return is_TCP()?(bool)tcph->fin:false;}
};
#endif
