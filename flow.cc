#include "flow.h"
#include "configure.h"

using namespace std;

void History::printHistory() {
	cout << "[" << start_time_ << ":" << end_time_;
	cout << "] : [BPS: "	<< bps_;
	cout << ", BI_DIRECTION_BPS: " << bi_bps_;
	cout << "], [PPS: " << pps_;
	cout << ", BI_DIRECTION_PPS: " << bi_pps_;
	cout << "], [TCP_S: " << tcp_s_;
	cout << "], [TCP_F: " << tcp_f_;
	cout << "], [TCP_R: " << tcp_r_ << "]";

	if (alert_bps_ || alert_pps_ || alert_tcp_){
		cout << ANSI_COLOR_RED;
		cout << " [Alert: ";
		if(alert_bps_)
			cout << "BPS, ";
		if(alert_pps_)
			cout << "PPS, ";
		if(alert_tcp_)
			cout << "TCP, ";
		cout << "\b\b]";
		cout << ANSI_COLOR_RESET;
	}
	cout << endl;
}

void Flow::printFlow () {
	cout << ANSI_COLOR_CYAN;
	cout << "[" << saddr() << ":" << sport() << "] -> [" << daddr() << ":" << dport() << "]" << endl;
	cout << ANSI_COLOR_RESET;

	if(history_)
		cout << ANSI_COLOR_GREEN << "                            History" << ANSI_COLOR_RESET << endl;
	for(History *h=history_;h!=NULL;h=h->next){
		h->printHistory();
	}

	cout << ANSI_COLOR_GREEN << "                            Real Time" << ANSI_COLOR_RESET << endl;
	cout << "[BPS: "	<< rt_bps();
	cout << ", BI_DIRECTION_BPS: " << rt_bi_bps();
	cout << "], [PPS: " << rt_pps();
	cout << ", BI_DIRECTION_PPS: " << rt_bi_pps();
	cout << "], [TCP_S: " << rt_tcp_s();
	cout << "], [TCP_F: " << rt_tcp_f();
	cout << "], [TCP_R: " << rt_tcp_r() << "]";
	if (alert_bps() || alert_pps() || alert_tcp()){
		cout << ANSI_COLOR_RED;
		cout << " [Alert: ";
		if(alert_bps())
			cout << "BPS, ";
		if(alert_pps())
			cout << "PPS, ";
		if(alert_tcp())
			cout << "TCP, ";
		cout << "\b\b]";
		cout << ANSI_COLOR_RESET;
	}
	cout << endl << endl;
}

void Flow::everySecond (int ctime){	
	// This function is to be called in every 1 second.
	// regarding print function
	printFlow();
	opposite->printFlow();	

	updateSum();
	opposite->updateSum();

	if ((ctime - base_time_)>=60){ // When 1 min has passed from base_time
		// register history.
		registerHistory();
		opposite->registerHistory();	
		clearSum();
		opposite->clearSum();
	}

	// let's decrease the time
	for(map<uint32_t,unsigned int>::iterator it = wait_synack_.begin();it != wait_synack_.end(); ++it){
		it->second--;

		if(it->second <= 0){ // timeout!
			wait_synack_.erase(it);
			tcp_f_++;
		}	
	}

	for(map<uint32_t,unsigned int>::iterator it = wait_ack_.begin();it != wait_ack_.end(); ++it){
		it->second--;

		if(it->second <= 0){ // timeout!
			wait_ack_.erase(it);
			tcp_f_++;
		}
	}
}

void Flow::updateSum (){
	// Update sum variables.
	bps_sum_ += bps_;
	bps_ = 0;
	pps_sum_ += pps_;
	pps_ = 0;
	tcp_s_sum_ += tcp_s_;
	tcp_s_ = 0;
	tcp_f_sum_ += tcp_f_;
	tcp_f_ = 0;
}

void Flow::registerHistory (){
	History *h = new History(base_time_, base_time_+60, h_bps(), h_bi_bps(), h_pps(), h_bi_pps(), h_tcp_s(), h_tcp_f(), h_tcp_r());	

	if (history_){ // not first element
		history_tail_->next = h;
		history_tail_ = h;
	} else{ // first element
		history_ = h;
		history_tail_ = h;
	}	
	base_time_ += 60;
}

void Flow::clearSum (){
	bps_sum_ = 0;
	pps_sum_ = 0;
	tcp_s_sum_ = 0;
	tcp_f_sum_ = 0;
}

void Flow::got_syn (uint32_t seqN){
	wait_synack_[seqN+1] = TCP_TIMEOUT;
}

void Flow::got_synack (uint32_t ackN, uint32_t seqN){
	if(wait_synack_[ackN] > 0){ // valid connection exist!
		wait_synack_.erase(ackN);
		wait_ack_[seqN+1] = TCP_TIMEOUT;
	}
}

void Flow::got_ack (uint32_t ackN){
	if(wait_ack_[ackN] > 0){ // valid connection exist!
		wait_ack_.erase(ackN);
		tcp_s_++;
	}
}
