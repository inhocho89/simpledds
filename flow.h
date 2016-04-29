#ifndef __FLOW_H__
#define __FLOW_H__
#include <iostream>
#include <cfloat>
#include <map>
#include <arpa/inet.h>
#include <string.h>
#include "packet.h"
#include "configure.h"

class AdptPair {
private:	
	uint32_t addr_;
	uint16_t port_;
public:
	AdptPair (uint32_t addr, uint16_t port) : addr_(addr), port_(port) { }
	uint32_t addr() const {return addr_;}
	uint16_t port() const {return port_;}
	bool operator== (const AdptPair other) const{
		return ((addr_ == other.addr_) && (port_ == other.port_));
	}
	bool operator< (const AdptPair other) const{
		if(addr_ < other.addr_)
			return true;
		else if (addr_ > other.addr_)
			return false;
		else if (addr_ == other.addr_)
			return (port_ < other.port_);
	}
};

class FourTuple {
private:
	AdptPair src_;
	AdptPair dst_;
public:
	FourTuple (AdptPair src, AdptPair dst) : src_(src), dst_(dst) { }
	AdptPair src() const {return src_;}
	AdptPair dst() const {return dst_;}

	bool operator== (const FourTuple other) const{
		return ((src_ == other.src_) && (dst_ == other.dst_));
	}

	bool operator< (const FourTuple other) const{
		if (src_ < other.src_)
			return true;
		else if (src_ == other.src_)
			return (dst_ < other.dst_);
		else
			return false;
	}
};

class FTCompare {
public:
	bool operator() (const FourTuple& x, const FourTuple& y) const{
		return (x<y);
	}
};

class History {
private:
	unsigned int start_time_;
	unsigned int end_time_;
	double bps_;
	double bi_bps_;
	double pps_;
	double bi_pps_;
	int tcp_s_;
	int tcp_f_;
	double tcp_r_;
	bool alert_bps_;
	bool alert_pps_;
	bool alert_tcp_;
public:
	History *next;
	History (unsigned int start_time, unsigned int end_time, double bps, double bi_bps, double pps, double bi_pps, int tcp_s, int tcp_f, double tcp_r) : start_time_ (start_time), end_time_ (end_time), bps_ (bps), bi_bps_ (bi_bps), pps_ (pps), bi_pps_ (bi_pps), tcp_s_ (tcp_s), tcp_f_ (tcp_f), tcp_r_ (tcp_r), alert_bps_ (false), alert_pps_ (false), alert_tcp_ (false){
		
		if ((MAX_BPS > 0.0) && (bps_ >= MAX_BPS))
			alert_bps_ = true;
		if ((MAX_PPS > 0.0) && (pps_ >= MAX_PPS))
			alert_pps_ = true;
		if ((MAX_TCP > 0.0) && (tcp_r_ >= MAX_TCP))
			alert_tcp_ = true;
		next = NULL;
	}
	void printHistory();
};

class Flow {
private:
	AdptPair src_;
	AdptPair dst_;

	char saddr_str_[16];
	char daddr_str_[16];
	struct sockaddr_in source_;
	struct sockaddr_in dest_;
	History *history_;
	History *history_tail_;

	unsigned int base_time_;
	int bps_sum_;
	int bps_;
	int pps_sum_;
	int pps_;
	int tcp_s_sum_;
	int tcp_s_;
	int tcp_f_sum_;
	int tcp_f_;

	std::map<uint32_t,unsigned int> wait_synack_;
	std::map<uint32_t,unsigned int> wait_ack_;
	
public:
	Flow *next;
	Flow *opposite;
	Flow (AdptPair src, AdptPair dst, int base_time) : src_(src), dst_(dst), history_(0), history_tail_(0), base_time_(base_time), bps_sum_(0), bps_(0), pps_sum_(0), pps_(0), tcp_s_sum_(0), tcp_s_(0), tcp_f_sum_(0), tcp_f_(0) {
		source_.sin_addr.s_addr = src.addr();
		dest_.sin_addr.s_addr = dst.addr();
		strncpy(saddr_str_,inet_ntoa(source_.sin_addr),15);
		strncpy(daddr_str_,inet_ntoa(dest_.sin_addr),15);	

		opposite = NULL;
		next = NULL;
	}

	char *saddr () {return saddr_str_;}
	char *daddr () {return daddr_str_;}
	uint16_t sport () {return src_.port();}
	uint16_t dport () {return dst_.port();}

	// real-time information
	int rt_bps() {return bps_;}
	int rt_bi_bps() {return (rt_bps() + opposite->rt_bps());}
	int rt_pps() {return pps_;}
	int rt_bi_pps() {return (rt_pps() + opposite->rt_pps());}
	int rt_tcp_s() {return tcp_s_;}
	int rt_tcp_f() {return tcp_f_;}
	double rt_tcp_r() {
		if (tcp_s_ == 0){
			if(tcp_f_ == 0)
				return 0.0;
			else
				return DBL_MAX;
		}else
			return ((double)tcp_f_/(double)tcp_s_);
	}
	bool alert_bps() {return ((MAX_BPS > 0.0) && (rt_bps() >= MAX_BPS));}
	bool alert_pps() {return ((MAX_PPS > 0.0) && (rt_pps() >= MAX_PPS));}
	bool alert_tcp() {return ((MAX_TCP > 0.0) && (rt_tcp_r() >= MAX_TCP));}

	// history information
	double h_bps() {return ((double)bps_sum_/60.0);}
	double h_bi_bps() {return (h_bps() + opposite->h_bps());}
	double h_pps() {return ((double)pps_sum_/60.0);}
	double h_bi_pps() {return (h_pps() + opposite->h_pps());}
	double h_tcp_s() {return tcp_s_sum_;}
	double h_tcp_f() {return tcp_f_sum_;}
	double h_tcp_r() {
		if (tcp_s_sum_ ==0){
			if(tcp_f_sum_ == 0)
				return 0.0;
			else
				return DBL_MAX;		
		}else
			return ((double)tcp_f_sum_/(double)tcp_s_sum_);
	}
	
	void tcp_conn_success () {tcp_s_++;}
	void tcp_conn_failed () {tcp_f_++;}

	void got_packet(int bytes){
		bps_ += bytes;
		pps_++;
	}

	void printFlow ();
	void everySecond (int ctime);
	void updateSum ();
	void registerHistory ();
	void clearSum ();
	void got_syn (uint32_t seqN);
	void got_synack (uint32_t ackN, uint32_t seqN);
	void got_ack (uint32_t ackN);
};
#endif
