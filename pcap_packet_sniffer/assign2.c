#define __USE_BSD 
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>


	struct round_trip {
		uint16_t seq_number;
		//uint16_t bytes_sent;
		uint16_t expected_ack_number;
		time_t start, stop;
   		double final_time;
	};

	struct connection {
		char ip_src[INET_ADDRSTRLEN]; /*source ip*/
 		char ip_dst[INET_ADDRSTRLEN]; /*destination ip*/
 		uint16_t port_src; /*source port number*/
 		uint16_t port_dst; /*destination port number*/ 
 		int syn_count; /*flag count*/
		int fin_count;
		int rst_count;
		time_t starting_time;
 		time_t ending_time;
		time_t duration;
		int num_packet_src; /*number of packets sent out by source*/
		int num_packet_dst; /*number of packets sent out by destination*/
		int num_total_packets;
		int cur_data_len_src; /*num data bytes*/
		int cur_data_len_dst; /*num data bytes*/
		int cur_total_data_len;
		uint16_t max_win_size; /*max window size*/
		uint16_t min_win_size; /*min window size*/
		uint16_t total_win_size;
		double sum_win_size;
		struct round_trip rtt_ary_src[1000]; /*assume 1000*/
		int rtt_ary_src_len; /*the size of the rtt_ary_src array*/
		struct round_trip rtt_ary_dst[1000]; /*assume 1000*/
		int rtt_ary_dst_len; /*the size of the rtt_ary_dst array*/
		int is_set; 
	};

	/*GLOBAL VARIABLES
	**************************************/
	/**/ struct connection conns[1000];//*
	/**/ int curr_conns = 0;//           *
	/**/ int used_conn; //               *
	/**/ int total_resets = 0;//         *
	/**/ int curr_caplen;//              *
	/**/ struct timeval start;//         *
	/*************************************
	GLOBAL VARIABLES
	*/

	void calc_RTT(struct tcphdr *tcphdr){
		int i = 0;
		printf("%d ", conns[used_conn].rtt_ary_src[i].expected_ack_number);
		printf("%d\n", ntohs(tcphdr->th_seq));
		for(i = 0; i<=conns[used_conn].rtt_ary_src_len; i++){
			if((conns[used_conn].rtt_ary_src[i].expected_ack_number) == ntohs(tcphdr->th_ack)){
				printf("WE'RE HERE\n");
				conns[used_conn].rtt_ary_src[i].stop = start_init.tv_sec;
				conns[used_conn].rtt_ary_src[i].final_time = (conns[used_conn].rtt_ary_src[i].stop - conns[used_conn].rtt_ary_src[i].start);
			}
		}
	}

	int check_conn(struct tcphdr *tcphdr, struct ip *ip){
		char ip_dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);
		char ip_src[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
		int is_unique = 0;
		if(curr_conns == 0){
			//SETS USED CONN FOR SYN/FIN/RST COUNT
			used_conn = 0;
			//SETS STARTING TIME FOR CONN
			conns[0].starting_time = start.tv_sec;
			//4-TUPLE
			strcpy(conns[0].ip_src,ip_src);
			strcpy(conns[0].ip_dst, ip_dst);
			conns[0].port_src = ntohs(tcphdr->th_sport);
			conns[0].port_dst = ntohs(tcphdr->th_dport);
			//STARTS PACKET COUNT
			conns[0].num_packet_src++;
			conns[0].num_total_packets++;
			//STARTS BYTE COUNT
			conns[0].cur_data_len_src += curr_caplen;
			//STARTS WINDOW COUNT
			conns[0].max_win_size = ntohs(tcphdr->th_win);
			conns[0].min_win_size = ntohs(tcphdr->th_win);
			conns[0].total_win_size = ntohs(tcphdr->th_win);
			//STARTS RTT CALCULATIONS
			conns[0].rtt_ary_src_len = 0;
			conns[0].rtt_ary_dst_len = 0;
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].seq_number = ntohs(tcphdr->th_seq);
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].expected_ack_number = ntohs(tcphdr->th_seq)+ntohs(curr_caplen);
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].start = clock();
			curr_conns++; //INCREMENTS AMOUNT OF CONNS
		}
		else{
			int i;
			for(i=0; i<curr_conns; i++){
				if((((strcmp(conns[i].ip_src, ip_src) == 0)) && (strcmp(conns[i].ip_dst, ip_dst) == 0))){
					if(((conns[i].port_src == ntohs(tcphdr->th_sport)) && (conns[i].port_dst == ntohs(tcphdr->th_dport)))) {
						if(ntohs(tcphdr->th_win)>conns[i].max_win_size){
							conns[i].max_win_size = tcphdr->th_win;
						}
						if(ntohs(tcphdr->th_win) < conns[i].min_win_size){
							conns[i].min_win_size = ntohs(tcphdr->th_win);
						}
						conns[i].total_win_size = conns[i].total_win_size + ntohs(tcphdr->th_win);
						conns[i].ending_time = start.tv_sec;
						conns[i].num_packet_src++;
						conns[i].num_total_packets++;
						used_conn = i;
						conns[i].rtt_ary_src_len++;
						conns[i].rtt_ary_src[conns[i].rtt_ary_src_len].seq_number = tcphdr->th_seq;
						conns[i].rtt_ary_src[conns[i].rtt_ary_src_len].expected_ack_number = tcphdr->th_seq+curr_caplen;
						conns[i].cur_data_len_src += curr_caplen;
						is_unique = 0;
						break;	
					}
				}
				if(((strcmp(conns[i].ip_src, ip_dst) == 0)) && (strcmp(conns[i].ip_dst, ip_src) == 0)) {
					if((conns[i].port_dst == ntohs(tcphdr->th_sport)) && (conns[i].port_src == ntohs(tcphdr->th_dport))) {
						if(ntohs(tcphdr->th_win) > conns[i].max_win_size){
							conns[i].max_win_size = ntohs(tcphdr->th_win);
						}
						if(ntohs(tcphdr->th_win) < conns[i].min_win_size){
							conns[i].min_win_size = ntohs(tcphdr->th_win);
						}
						conns[i].total_win_size = conns[i].total_win_size + ntohs(tcphdr->th_win);
						conns[i].ending_time = start.tv_sec;
						conns[i].num_packet_dst++;
						conns[i].num_total_packets++;
						used_conn = i;
						calc_RTT(tcphdr);
						conns[i].cur_data_len_dst += curr_caplen;
						is_unique = 0;
						break;	
					}
				}
				is_unique = 1;		
			}
		}

		if(is_unique == 1){
			//SETS USED CONN FOR SYN/FIN/RST COUNT
			used_conn = curr_conns;
			//SETS STARTING TIME FOR CONN
			conns[curr_conns].starting_time = start.tv_sec;
			//4-TUPLE
			strcpy(conns[curr_conns].ip_src,ip_src);
			strcpy(conns[curr_conns].ip_dst, ip_dst);
			conns[curr_conns].port_src = ntohs(tcphdr->th_sport);
			conns[curr_conns].port_dst = ntohs(tcphdr->th_dport);
			//STATS PACKET COUNT
			conns[curr_conns].num_packet_src++;
			conns[curr_conns].num_total_packets++;
			//STARTS BYTE COUNT
			conns[curr_conns].cur_data_len_src += curr_caplen;
			//STARTS WINDOW COUNT
			conns[curr_conns].max_win_size = ntohs(tcphdr->th_win);
			conns[curr_conns].min_win_size = ntohs(tcphdr->th_win);
			conns[curr_conns].total_win_size = ntohs(tcphdr->th_win);
			//STARTS RTT CALCULATIONS
			conns[curr_conns].rtt_ary_src_len = 0;
			conns[curr_conns].rtt_ary_dst_len = 0;
			conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].seq_number = tcphdr->th_seq;
			conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].expected_ack_number = tcphdr->th_seq+curr_caplen;
			time(&conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].start);
			curr_conns++; // INCREMENTS AMOUNT OF CONNS
			return 0;
		}

		return 1;
	}



	void ReadTraceFile(const unsigned char *packet, struct timeval ts, unsigned int capture_len){
		struct ip *ip;
		struct tcphdr *tcphdr;
		unsigned int IP_header_length;
		
		packet += sizeof(struct ether_header);
		capture_len -= sizeof(struct ether_header);

		if(capture_len < sizeof(struct ip)){
			printf("Ya fucked up fam\n");
			return;
		}

		ip = (struct ip*) packet;
		IP_header_length = ip->ip_hl * 4;

		if(capture_len < IP_header_length){
			printf("YA FUCKED up FAM\n");
			return;
		}

		if(ip->ip_p != IPPROTO_TCP){
			printf("ffdada");
			return;
		}

		packet+= IP_header_length;
		capture_len -= IP_header_length;


		if (capture_len < sizeof(struct tcphdr))
		{
			printf("THEY DONT WANT NUTHIN");
			return;
		}
		tcphdr = (struct tcphdr*) packet;
		int is_unique = check_conn(tcphdr, ip);
			if(tcphdr->syn){
				conns[used_conn].syn_count++;
			}
			if(tcphdr->fin){
				conns[used_conn].fin_count++;
			}
			if(tcphdr->rst){
				if(conns[used_conn].rst_count == 0){
					total_resets++;
				}
				conns[used_conn].rst_count++;
			}
	}


	int main(int argc, char *argv[])
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle;
		const unsigned char *packet;
		struct bpf_program fp;
		char filter_exp[] = "tcp";
		bpf_u_int32 netmask;
		unsigned int packet_counter = 0;
		struct pcap_pkthdr header;
		int total_complete_conns = 0;
		int still_open_conns = 0;
		//TIME
		time_t mean_time_duration = 0;
		time_t min_time_duration;
		time_t max_time_duration;
		//PACKETS
		int mean_packets = 0;
		int min_packets;
		int max_packets;
		//WINDOW SIZE
		int mean_window_size = 0;
		int min_window_size;
		int max_window_size;
		//RTT
		double min_RTT_time, max_RTT_time;
		double mean_RTT_time = 0.00;
		int total_RTT = 0;

		handle = pcap_open_offline(argv[1], errbuf);
		 if (handle == NULL) {
		 	fprintf(stderr, "Couldn't open device %s\n", errbuf);
		 return(2);
	 	}
		if(pcap_compile(handle, &fp, filter_exp, 0, netmask) == -1){
			fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
			return(2);	
		};

		if(pcap_setfilter(handle, &fp) == -1){
			fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
			return(2);
		};
		while ((packet = pcap_next(handle,&header)) != NULL) {
			start = header.ts;
			curr_caplen = header.caplen;
			ReadTraceFile(packet, header.ts, header.caplen);
			packet_counter++;
		}
		pcap_close(handle);

		int i = 0;
		int set_packs = 0;
		int total_packets = 0;
		//min_packets, max_packets = conns[0].num_total_packets;
		//printf("min packets: %d\n", min_packets);
		//<-- PART A -->//

		printf("A)Total Connections = %d\n-----------------------------------------------------------\nB)Connections' Details:\n", curr_conns);
		// <-- PART B -->//	
		for(i = 0; i<curr_conns; i++){
			/*printf("Connection %d:\n", i+1);
			printf("IP source: %s\n", conns[i].ip_src);
			printf("IP destination: %s\n", conns[i].ip_dst);
			printf("Source Port: %d\n", conns[i].port_src);
			printf("Source Destination: %d\n", conns[i].port_dst);
			printf("Status: S%dF%d\n", conns[i].syn_count, conns[i].fin_count);*/
			if(conns[i].syn_count>=1 && conns[i].fin_count>=1){
				if(set_packs == 0){
					min_time_duration = max_time_duration = (conns[i].ending_time - conns[i].starting_time);
					min_packets = max_packets = conns[i].num_total_packets;
					max_window_size = conns[i].max_win_size;
					min_window_size = conns[i].min_win_size;
					set_packs++;
				}
				printf("number of packets: %d\n", conns[i].num_total_packets);
				int j = 0;
				mean_time_duration = mean_time_duration + (conns[i].ending_time - conns[i].starting_time); //TIME
				mean_packets = mean_packets+(conns[i].num_total_packets); 
				//total_packets = total_packets += conns[i].num_total_packets; //PACKETS
				mean_window_size = mean_window_size +(conns[i].total_win_size/conns[i].num_total_packets); //WINDOW
				for(j; j<=conns[i].rtt_ary_src_len;j++){
					if(total_RTT == 0){
						min_RTT_time, max_RTT_time = conns[i].rtt_ary_src[j].final_time;
					}
					else{
						if(conns[i].rtt_ary_src[j].final_time > min_RTT_time){
							min_RTT_time = conns[i].rtt_ary_src[j].final_time;
						}
						if(conns[i].rtt_ary_src[j].final_time < max_RTT_time){
							max_RTT_time = conns[i].rtt_ary_src[j].final_time;
						}
					}
					mean_RTT_time = mean_RTT_time+conns[i].rtt_ary_src[j].final_time;
					total_RTT++;
				} //RTT
				/*printf("Start time: %ld\n", conns[i].starting_time);
				printf("End time: %ld\n", conns[i].ending_time);
				printf("Total duration: %ld\n", conns[i].duration = conns[i].ending_time - conns[i].starting_time);
				printf("Number of packets sent from Source to Destination: %d\n", conns[i].num_packet_src);
				printf("Number of packets sent from Destination to Source: %d\n", conns[i].num_packet_dst);
				printf("Total number of packets sent: %d\n", conns[i].num_total_packets);
				printf("Number of databyes sent from Source to Destination: %d\n", conns[i].cur_data_len_src);
				printf("Number of databyes sent from Destination to Source: %d\n", conns[i].cur_data_len_dst);
				printf("Total number of databyes sent: %d\n", conns[i].cur_data_len_src+conns[i].cur_data_len_dst);*/
				total_complete_conns++;
				// TIME //
				if(conns[i].duration < min_time_duration){
				min_time_duration = conns[i].duration;
				}
				if(conns[i].duration > max_time_duration){
					max_time_duration = conns[i].duration;
				}
				// PACKETS //
				if(conns[i].num_total_packets < min_packets){
					printf("min packet: %d\n", conns[i].num_total_packets);
					min_packets = conns[i].num_total_packets;
				}
				if(conns[i].num_total_packets > max_packets){
					max_packets = conns[i].num_total_packets;
				}
				// WINDOW //
				if(conns[i].min_win_size < min_window_size){
					min_window_size = conns[i].min_win_size;
				}
				if(conns[i].max_win_size > max_window_size){
					max_window_size = conns[i].max_win_size;
				}
			}


			if(conns[i].fin_count == 0){
				still_open_conns++;
			}
			/*// TIME //
			if(conns[i].duration < min_time_duration){
				min_time_duration = conns[i].duration;
			}
			if(conns[i].duration > max_time_duration){
				max_time_duration = conns[i].duration;
			}
			// PACKETS //
			if(conns[i].num_total_packets < min_packets){
				min_packets = conns[i].num_total_packets;
			}
			if(conns[i].num_total_packets > max_packets){
				max_packets = conns[i].num_total_packets;
			}
			// WINDOW //
			if(conns[i].min_win_size < min_window_size){
				min_window_size = conns[i].min_win_size;
			}
			if(conns[i].max_win_size > max_window_size){
				max_window_size = conns[i].max_win_size;
			}*/
			printf("END\n");
			printf("+++++++++++++++++++++++++++++++++++++\n");
		}
		mean_time_duration = mean_time_duration/total_complete_conns;
		mean_packets = mean_packets/total_complete_conns;
		printf("%d\n", mean_window_size);
		printf("%d\n", total_packets);
		mean_window_size = mean_window_size/total_complete_conns;
		mean_RTT_time = mean_RTT_time/total_RTT;
		//<-- PART C --> //
		printf("C) General\n");
		printf("Total Number of Complete TCP Connections: %d\n", total_complete_conns);
		printf("Number of reset TCP connections: %d\n", total_resets);
		printf("Number of TCP connections still open when the trace ended: %d\n-----------------------------------------------------------\n", still_open_conns);
		//<-- PART D --> //
		printf("D) Complete TCP Connections:\n");
		// <-- TIME --> //
		printf("Minimum time duration: %ld\n", min_time_duration);
		printf("Mean time duration: %ld\n", mean_time_duration);
		printf("Maximum time duration: %ld\n\n", max_time_duration);
		// <-- RTT --> //
		printf("Maximum RTT time: %f\n", min_RTT_time);
		printf("Mean RTT time: %f\n", max_RTT_time);
		printf("Maximum RTT time: %f\n\n", mean_RTT_time);
		// <-- Packets --> //
		printf("Minimum number of packets including sent/recieved: %d\n", min_packets);
		printf("Mean number of packets including sent/recieved: %d\n", mean_packets);
		printf("Maximum number of packets including sent/recieved: %d\n\n", max_packets);
		// <-- Window Size --> //
		printf("Minimum receive window sizes including both send/received: %d\n", min_window_size);
		printf("Mean receive window sizes including both send/received: %d\n", mean_window_size);
		printf("Maximum receive window sizes including both send/received: %d\n-----------------------------------------------------------\n", max_window_size);
		
		return(0);
	}