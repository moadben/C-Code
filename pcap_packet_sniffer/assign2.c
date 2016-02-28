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


	// **************** STRUCTS ************** //
	struct round_trip {
		uint16_t seq_number;
		//uint16_t bytes_sent;
		uint32_t expected_ack_number;
		double start, stop;
		int has_ack;
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
		double starting_time;
 		double ending_time;
		double duration;
		int num_packet_src; /*number of packets sent out by source*/
		int num_packet_dst; /*number of packets sent out by destination*/
		int num_total_packets;
		int cur_data_len_src; /*num data bytes*/
		int cur_data_len_dst; /*num data bytes*/
		int cur_total_data_len;
		uint16_t max_win_size; /*max window size*/
		uint16_t min_win_size; /*min window size*/
		long total_win_size;
		double sum_win_size;
		struct round_trip rtt_ary_src[1000]; /*assume 1000*/
		int rtt_ary_src_len; /*the size of the rtt_ary_src array*/
		struct round_trip rtt_ary_dst[1000]; /*assume 1000*/
		int rtt_ary_dst_len; /*the size of the rtt_ary_dst array*/
		int is_set;
	};

	// **************** END OF STRUCTS ************** //


	/*GLOBAL VARIABLES
	**************************************/
	/**/ struct connection conns[1000];//*
	/**/ int curr_conns = 0;//           *
	/**/ int used_conn; //               *
	/**/ int total_resets = 0;//         *
	/**/ int curr_caplen;//              *
	/**/ struct timeval start;//         *
	/**/ struct timeval start_init;//     *// THE INITIAL TIME OF FIRST PACKET.
	/*************************************
	GLOBAL VARIABLES
	*/

	int temp_conn_count = 0;


	// **************** RTT CALCULATIONS ************** //
	void calc_RTT(struct tcphdr *tcphdr){ //SOURCE
		int i;
		for(i = 0; i<conns[used_conn].rtt_ary_src_len; i++){
			if(((conns[used_conn].rtt_ary_src[i].expected_ack_number) == ntohl(tcphdr->th_ack)) && (conns[used_conn].rtt_ary_src[i].has_ack == 0)){
				conns[used_conn].rtt_ary_src[i].stop =  ((double)start.tv_sec+(double)(start.tv_usec/1000000.0)) - ((double)(start_init.tv_sec) + (double)(start_init.tv_usec/1000000.0));;
				conns[used_conn].rtt_ary_src[i].final_time = ((conns[used_conn].rtt_ary_src[i].stop - conns[used_conn].rtt_ary_src[i].start));
				conns[used_conn].rtt_ary_src[i].has_ack = 1;
				break;

			}
		}
	}

	void calc_RTT_dst(struct tcphdr *tcphdr){ // DESTINATION
		int i;
		for(i = 0; i<conns[used_conn].rtt_ary_dst_len; i++){
			if(((conns[used_conn].rtt_ary_dst[i].expected_ack_number) == ntohl(tcphdr->th_ack)) && (conns[used_conn].rtt_ary_dst[i].has_ack == 0)){
				conns[used_conn].rtt_ary_dst[i].stop =  ((double)start.tv_sec+(double)(start.tv_usec/1000000.0)) - ((double)(start_init.tv_sec) + (double)(start_init.tv_usec/1000000.0));;
				conns[used_conn].rtt_ary_dst[i].final_time = ((conns[used_conn].rtt_ary_dst[i].stop - conns[used_conn].rtt_ary_dst[i].start));
				conns[used_conn].rtt_ary_dst[i].has_ack = 1;
				break;
			}
		}
	}
	// **************** END OF RTT CALCULATIONS ************** //


	// **************** READS PACKETS ***************** //

	int check_conn(struct tcphdr *tcphdr, struct ip *ip, int IP_header_length){
		char ip_dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);
		char ip_src[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
		int is_unique = 0;

		// FIRST CONNECTION //
		if(curr_conns == 0){
			//SETS USED CONN FOR SYN/FIN/RST COUNT
			used_conn = 0;
			//SETS STARTING TIME FOR CONN
			conns[0].starting_time = ((double)start.tv_sec+(double)(start.tv_usec/1000000.0)) - ((double)(start_init.tv_sec) + (double)(start_init.tv_usec/1000000.0));
			//4-TUPLE
			strcpy(conns[0].ip_src,ip_src);
			strcpy(conns[0].ip_dst, ip_dst);
			conns[0].port_src = ntohs(tcphdr->th_sport);
			conns[0].port_dst = ntohs(tcphdr->th_dport);
			//STARTS PACKET COUNT
			conns[0].num_packet_src++;
			conns[0].num_total_packets++;
			//STARTS BYTE COUNT
			conns[0].cur_data_len_src += (curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
			//STARTS WINDOW COUNT
			conns[0].max_win_size = ntohs(tcphdr->th_win);
			conns[0].min_win_size = ntohs(tcphdr->th_win);
			conns[0].total_win_size = ntohs(tcphdr->th_win);
			//STARTS RTT CALCULATIONS
			conns[0].rtt_ary_src_len = 0;
			conns[0].rtt_ary_dst_len = 0;
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].seq_number = (tcphdr->th_seq);
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].expected_ack_number = ntohl(tcphdr->th_seq)+(curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].start = conns[0].starting_time;
			conns[0].rtt_ary_src[conns[0].rtt_ary_src_len].has_ack = 0;
			conns[0].rtt_ary_src_len++; //INCREMENTS AMOUNT OF RTT'S
			curr_conns++; //INCREMENTS AMOUNT OF CONNS
		}
		
		// NON-NEW CONNECTIONS //
		else{
			int i;
			for(i=0; i<curr_conns; i++){
				if((((strcmp(conns[i].ip_src, ip_src) == 0)) && (strcmp(conns[i].ip_dst, ip_dst) == 0))){
					if(((conns[i].port_src == ntohs(tcphdr->th_sport)) && (conns[i].port_dst == ntohs(tcphdr->th_dport)))) {
						if(ntohs(tcphdr->th_win)>conns[i].max_win_size){
							conns[i].max_win_size = ntohs(tcphdr->th_win);
						}
						if(ntohs(tcphdr->th_win) < conns[i].min_win_size){
							conns[i].min_win_size = ntohs(tcphdr->th_win);
						}
						conns[i].total_win_size = conns[i].total_win_size + ntohs(tcphdr->th_win);
						conns[i].ending_time = ((double)start.tv_sec+(double)(start.tv_usec/1000000.0)) - ((double)(start_init.tv_sec) + (double)(start_init.tv_usec/1000000.0));
						conns[i].num_packet_src++;
						conns[i].num_total_packets++;
						used_conn = i;
						calc_RTT_dst(tcphdr);
						//RTT START
						int expected_ack_number = ntohl(tcphdr->th_seq)+(curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
						int already_in = 0;
						int j; // USED FOR FOR LOOP
						for(j = 0; j<conns[i].rtt_ary_src_len; j++){
							if(expected_ack_number == (conns[i].rtt_ary_src[j].expected_ack_number)){
								already_in = 1;
								break;
							}
						}

						if(already_in == 0){
							conns[i].rtt_ary_src[conns[i].rtt_ary_src_len].seq_number = (tcphdr->th_seq);
							conns[i].rtt_ary_src[conns[i].rtt_ary_src_len].expected_ack_number = expected_ack_number;
							conns[i].rtt_ary_src[conns[i].rtt_ary_src_len].start = conns[i].ending_time;
							conns[i].rtt_ary_src[conns[i].rtt_ary_src_len].has_ack = 0;
							conns[i].rtt_ary_src_len++;
						}
						//RTT DONE
						conns[i].cur_data_len_src += (curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
						is_unique = 0;
						temp_conn_count++;
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
						conns[i].ending_time =((double)start.tv_sec+(double)(start.tv_usec/1000000.0)) - ((double)(start_init.tv_sec) + (double)(start_init.tv_usec/1000000.0));;
						conns[i].num_packet_dst++;
						conns[i].num_total_packets++;
						used_conn = i;
						conns[i].cur_data_len_dst += (curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
						//printf("%d",conns[used_conn].rtt_ary_src_len);
						calc_RTT(tcphdr);

						int expected_ack_number = ntohl(tcphdr->th_seq)+(curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
						int already_in = 0;
						int j;
						for(j = 0; j<conns[i].rtt_ary_dst_len; j++){
							if(expected_ack_number == (conns[i].rtt_ary_dst[j].expected_ack_number)){
								already_in = 1;
								break;
							}
						}
						if(already_in == 0){
							conns[i].rtt_ary_dst[conns[i].rtt_ary_dst_len].seq_number = (tcphdr->th_seq);
							conns[i].rtt_ary_dst[conns[i].rtt_ary_dst_len].expected_ack_number = expected_ack_number;
							conns[i].rtt_ary_dst[conns[i].rtt_ary_dst_len].start = conns[i].ending_time;
							conns[i].rtt_ary_dst[conns[i].rtt_ary_dst_len].has_ack = 0;
							conns[i].rtt_ary_dst_len++;
						}
						is_unique = 0;
						break;
					}
				}
				is_unique = 1;
			}
		}

		// NEW CONNECTIONS //
		if(is_unique == 1){
			//SETS USED CONN FOR SYN/FIN/RST COUNT
			used_conn = curr_conns;
			//SETS STARTING TIME FOR CONN
			conns[curr_conns].starting_time = ((double)start.tv_sec+(double)(start.tv_usec/1000000.0)) - ((double)(start_init.tv_sec) + (double)(start_init.tv_usec/1000000.0));;
			//4-TUPLE
			strcpy(conns[curr_conns].ip_src,ip_src);
			strcpy(conns[curr_conns].ip_dst, ip_dst);
			conns[curr_conns].port_src = ntohs(tcphdr->th_sport);
			conns[curr_conns].port_dst = ntohs(tcphdr->th_dport);
			//STATS PACKET COUNT
			conns[curr_conns].num_packet_src++;
			conns[curr_conns].num_total_packets++;
			//STARTS BYTE COUNT
			conns[curr_conns].cur_data_len_src += (curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
			//STARTS WINDOW COUNT
			conns[curr_conns].max_win_size = ntohs(tcphdr->th_win);
			conns[curr_conns].min_win_size = ntohs(tcphdr->th_win);
			conns[curr_conns].total_win_size = ntohs(tcphdr->th_win);
			//STARTS RTT CALCULATIONS
			conns[curr_conns].rtt_ary_src_len = 0;
			conns[curr_conns].rtt_ary_dst_len = 0;
			conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].seq_number = (tcphdr->th_seq);
			conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].expected_ack_number = ntohl(tcphdr->th_seq)+(curr_caplen-IP_header_length-sizeof(struct ether_header)-(tcphdr->th_off*4));
			conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].start = conns[curr_conns].starting_time;
			conns[curr_conns].rtt_ary_src[conns[curr_conns].rtt_ary_src_len].has_ack = 0;
			conns[curr_conns].rtt_ary_src_len++;
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
			printf("Packet too small\n");
			return;
		}

		ip = (struct ip*) packet;
		IP_header_length = ip->ip_hl * 4;

		if(capture_len < IP_header_length){
			printf("Packet too small\n");
			return;
		}

		if(ip->ip_p != IPPROTO_TCP){
			printf("Packet is not TCP\n");
			return;
		}

		packet+= IP_header_length;
		capture_len -= IP_header_length;


		if (capture_len < sizeof(struct tcphdr))
		{
			printf("Length of tcphdr too short\n");
			return;
		}
		tcphdr = (struct tcphdr*) packet;
		int is_unique = check_conn(tcphdr, ip, IP_header_length);
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

		//   INITIALIZES THE VALUES NEEDED TO CALCULATE MINS, MEANS, MAXES AND CONNECTIONS.  //

		int total_complete_conns = 0;
		int still_open_conns = 0;
		//TIME
		double mean_time_duration = 0.000;
		double min_time_duration;
		double max_time_duration;
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

		//     END OF INITIALIZATIONS    //

		//     OPENS PCAP FILE          //
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
		int x = 0;
		while ((packet = pcap_next(handle,&header)) != NULL) {
			if(x==0){
				start_init = header.ts;
				x++;
			}
			start = header.ts;
			curr_caplen = header.caplen;
			ReadTraceFile(packet, header.ts, header.len);
			packet_counter++;
		}
		pcap_close(handle);
		//     END OF READING PCAP FILE    //
		int i = 0;
		int set_packs = 0;
		int total_packets = 0;

		//<-- PART A -->//

		printf("A)Total Connections = %d\n-----------------------------------------------------------\nB)Connections' Details:\n", curr_conns);

		// <-- PART B -->//

		for(i = 0; i<curr_conns; i++){
			printf("Connection %d:\n", i+1);
			printf("IP source: %s\n", conns[i].ip_src);
			printf("IP destination: %s\n", conns[i].ip_dst);
			printf("Source Port: %d\n", conns[i].port_src);
			printf("Destination Port: %d\n", conns[i].port_dst);
			printf("Status: S%dF%d\n", conns[i].syn_count, conns[i].fin_count);
			if(conns[i].syn_count>=1 && conns[i].fin_count>=1){
				if(set_packs == 0){
					min_time_duration = max_time_duration = (conns[i].ending_time - conns[i].starting_time);
					min_packets = max_packets = conns[i].num_total_packets;
					max_window_size = conns[i].max_win_size;
					min_window_size = conns[i].min_win_size;
					set_packs++;
				}
				int j;
				mean_time_duration = mean_time_duration + (conns[i].ending_time - conns[i].starting_time); //TIME
				mean_packets = mean_packets+(conns[i].num_total_packets); //PACKETS
				mean_window_size = mean_window_size +(conns[i].total_win_size); //WINDOW
				total_packets = total_packets + conns[i].num_total_packets; //TOTAL PACKETS
				//SRC
				for(j=0; j<conns[i].rtt_ary_src_len;j++){ //RTT
					if(conns[i].rtt_ary_src[j].has_ack == 1){
						if(total_RTT == 0){
							max_RTT_time = min_RTT_time = conns[i].rtt_ary_src[j].final_time;
							//total_RTT++;
						}
						else{
							if(conns[i].rtt_ary_src[j].final_time > max_RTT_time){
								max_RTT_time = conns[i].rtt_ary_src[j].final_time;
							}
							if(conns[i].rtt_ary_src[j].final_time < min_RTT_time){
								min_RTT_time = conns[i].rtt_ary_src[j].final_time;
							}
						}
						mean_RTT_time = mean_RTT_time+conns[i].rtt_ary_src[j].final_time;
						total_RTT++;
					}
				}
				//DST
				for(j=0; j<conns[i].rtt_ary_dst_len;j++){ //RTT
					if(conns[i].rtt_ary_dst[j].has_ack == 1){
						if(total_RTT == 0){
							max_RTT_time = min_RTT_time = conns[i].rtt_ary_dst[j].final_time;
							//total_RTT++;
						}
						else{
							if(conns[i].rtt_ary_dst[j].final_time > max_RTT_time){
								max_RTT_time = conns[i].rtt_ary_dst[j].final_time;
							}
							if(conns[i].rtt_ary_dst[j].final_time < min_RTT_time){
								min_RTT_time = conns[i].rtt_ary_dst[j].final_time;
							}
						}
						mean_RTT_time = mean_RTT_time+conns[i].rtt_ary_dst[j].final_time;
						total_RTT++;
					}
				}
				// PRINTS COMPLETE CONNECTION STATS //

			 	printf("Start time: %.3f\n", conns[i].starting_time);
				printf("End time: %.3f\n", conns[i].ending_time);
				printf("Total duration: %.3f\n", conns[i].duration = conns[i].ending_time - conns[i].starting_time);
				printf("Number of packets sent from Source to Destination: %d\n", conns[i].num_packet_src);
				printf("Number of packets sent from Destination to Source: %d\n", conns[i].num_packet_dst);
				printf("Total number of packets sent: %d\n", conns[i].num_total_packets);
				printf("Number of databyes sent from Source to Destination: %d\n", conns[i].cur_data_len_src);
				printf("Number of databyes sent from Destination to Source: %d\n", conns[i].cur_data_len_dst);
				printf("Total number of databyes sent: %d\n", conns[i].cur_data_len_src+conns[i].cur_data_len_dst);
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

			// CALCULATES STILL OPEN CONNECTIONS //
			if(conns[i].fin_count == 0){
				still_open_conns++;
			}
			
			printf("END\n");
			printf("+++++++++++++++++++++++++++++++++++++\n");
		}
		mean_time_duration = mean_time_duration/total_complete_conns;
		mean_packets = mean_packets/total_complete_conns;
		mean_window_size = mean_window_size/total_packets;
		mean_RTT_time = mean_RTT_time/(total_RTT);
		//<-- PART C --> //
		printf("C) General\n");
		printf("Total Number of Complete TCP Connections: %d\n", total_complete_conns);
		printf("Number of reset TCP connections: %d\n", total_resets);
		printf("Number of TCP connections still open when the trace ended: %d\n-----------------------------------------------------------\n", still_open_conns);
		//<-- PART D --> //
		printf("D) Complete TCP Connections:\n");
		// <-- TIME --> //
		printf("Minimum time duration: %.3f\n", min_time_duration);
		printf("Mean time duration: %.3f\n", mean_time_duration);
		printf("Maximum time duration: %.3f\n\n", max_time_duration);
		// <-- RTT --> //
		printf("Minimum RTT time: %.3f\n", min_RTT_time);
		printf("Mean RTT time: %.3f\n", mean_RTT_time);
		printf("Maximum RTT time: %.3f\n\n", max_RTT_time);
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
