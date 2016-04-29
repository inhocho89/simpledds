#include "packet.h"

uint16_t Packet::sport () {
	if(is_TCP())
		return ntohs(tcph->source);
	else if(is_UDP())
		return ntohs(udph->source);
	else
		return (uint16_t)NULL;
}

uint16_t Packet::dport () {
	if (is_TCP())
		return ntohs(tcph->dest);
	else if (is_UDP())
		return ntohs(udph->dest);
	else
		return (uint16_t)NULL;
}
