//###############################################//
//    Simple DDoS Detector System (simple DDS)   //
//      Author: Inho Cho <inho00@kaist.ac.kr>    //
//            Last Update: 2016. 4. 27.          //
//###############################################//

#include <iostream>
#include <string>
#include <cstdlib>
#include <map>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>
#include "packet.h"
#include "flow.h"
#include "configure.h"

using namespace std;

double MAX_PPS = 0.0;
double MAX_BPS = 0.0;
double MAX_TCP = 0.0;

static unsigned int dds_clock = 0;	// clock.
static pcap_t *handle = 0;				// packet capture handler
static struct bpf_program *fp = 0;	// compiled filter program (expression)
static map<FourTuple,Flow*,FTCompare> flowMap;
static Flow *flowList = 0;
static Flow *flowTail = 0;

void got_packet (uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet){
	Packet pkt((uint8_t *)packet);
	AdptPair src(pkt.ip_saddr(), pkt.sport());
	AdptPair dst(pkt.ip_daddr(), pkt.dport());
	FourTuple atob(src, dst);
	FourTuple btoa(dst, src);
	Flow *f = flowMap[atob];
	Flow *fo = flowMap[btoa];

	if((f == NULL) && (fo == NULL)){
		f = new Flow(src, dst, dds_clock);
		fo = new Flow(dst, src, dds_clock);
		f->opposite = fo;
		fo->opposite = f;

		flowMap[atob] = f;
		flowMap[btoa] = fo;
		
		if (flowList){ // Not first element!
			flowTail->next = f;
			flowTail = f;
		}else{ // first element
			flowList = f;
			flowTail = f;
		}	
	}else if((f == NULL) || (fo == NULL)){
		cerr << "ERROR: Significant error. a->b exist but b->a does not exist." << endl;
	}

	f->got_packet(pkt.eth_length());

	if (pkt.tcp_syn() && !pkt.tcp_ack()) // SYN packet.
		f->got_syn (pkt.tcp_seqN());
	else if (pkt.tcp_syn() && pkt.tcp_ack()) // SYNACK packet.
		fo->got_synack (pkt.tcp_ackN(), pkt.tcp_seqN());
	else if (!pkt.tcp_syn() && pkt.tcp_ack()) // ACK packet.
		f->got_ack (pkt.tcp_ackN());
}

void intHandler (int dummy){
	cout << "Terminating..." << endl;
	// clean up when SIGINT signal is detected. (Ctrl + C)
	if(fp){
		pcap_freecode(fp);
		free (fp);
	}
	if(handle)
		pcap_close(handle);
	exit(EXIT_SUCCESS);
}

void everySecond (int signo){
	// This function is called every seconds.
	dds_clock++;
	system("clear");
	for(Flow *f=flowList;f!=NULL;f=f->next){
		f->everySecond(dds_clock);
	}
	cout << endl;	
	alarm (1);
}

void printUsage (void) {
	cout << "Usage: ./simpledds [-pps packets_per_second] [-bps bytes_per_second] [-tcp #_of_failed_TCP/#_of_successful_TCP]" << endl;
	exit(EXIT_FAILURE);
}

int main (int argc, char **argv){
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "ip and (tcp or udp)";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int i; // for loop iterator

	// space for fp
	fp = (struct bpf_program *)malloc(sizeof(struct bpf_program));

	// Check basic argument's condition
	if (argc%2 == 0)
		printUsage();

	// Parse arguments
	for(i = 1; i<argc; ++i){
		if (strlen(argv[i]) == 4){
			if(strcmp(argv[i], "-pps") == 0){
				double pps = atof(argv[++i]);
				if (pps > 0)
					MAX_PPS = pps;
				else{
					cerr << "Wrong argument: -pps argument should be greater than 0." << endl;
					exit(EXIT_FAILURE);
				}
			}else if(strcmp(argv[i], "-bps") == 0){
				double bps = atof(argv[++i]);
				if(bps > 0)
					MAX_BPS = bps;
				else{
					cerr << "Wrong argument: -bps argument should be greater than 0." << endl;
					exit(EXIT_FAILURE);
				}
			}else if(strcmp(argv[i], "-tcp") == 0){
				double tcp = atof(argv[++i]);
				if(tcp > 0)
					MAX_TCP = tcp;
				else{
					cerr << "Wrong argument: -tcp argumnet should be greater than 0." << endl;
					exit(EXIT_FAILURE);
				}
			}else{
				cerr << "Unknown option: " << argv[i] << endl;
				printUsage();
			}
		}else{
			cerr << "Unknown option: " << argv[i] << endl;
			printUsage();
		}
	}

	// Ctrl + C to terminate the process.
	signal(SIGINT, intHandler);

	signal(SIGALRM, everySecond);

	// Find a capture device.
	if (dev == NULL)
		dev = pcap_lookupdev(errbuf);
	if (dev == NULL){
		cerr << "ERROR: Couldn't find default device: " << errbuf << endl;
		cerr << "Try to execute with sudo permission." << endl;
		exit(EXIT_FAILURE);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		cerr << "ERROR: Couldn't get netmask for device " << dev << ": " << errbuf << endl;
		net = 0;
		mask = 0;
	}

	// open capture device
	handle = pcap_open_live (dev, 1518, 1, 1000, errbuf);
	if (handle == NULL){
		cerr << "ERROR: Coudln't open device " << dev << " : " << errbuf << endl;
		exit(EXIT_FAILURE);
	}

	// make sure dev is ethernet device.
	if (pcap_datalink(handle) != DLT_EN10MB){
		cerr << "ERROR: " << dev << " is not an Ethernet device." << endl;
		exit(EXIT_FAILURE);
	}

	// compile the filter expression
	if (pcap_compile(handle, fp, filter_exp, 0, net) == -1){
		cerr << "ERROR: Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
		exit(EXIT_FAILURE);
	}


	// apply the compiled filter
	if (pcap_setfilter(handle, fp) == -1){
		cerr << "ERROR: Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
		exit(EXIT_FAILURE);
	}

	alarm(1);
	pcap_loop(handle, 0, got_packet, NULL);

	if (fp){
		pcap_freecode(fp);
		free(fp);
	}
	if (handle)
		pcap_close (handle);
	exit(EXIT_SUCCESS);
}
