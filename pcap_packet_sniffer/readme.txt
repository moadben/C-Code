How to run server+client:

- Run makefile
- Enter: ./assign2 <cap file here>

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ABSTRACT: Sniffs a cap file and associates all tcp packets to their respective connection. Prints out:
		- The source IP/Port & Destination IP/Port, Status, Start & Finish time, duration, packets & bytes sent from source and destination along with their respective totals. For incomplete connections everything past the Status is not printed.
		- The total amount of connections, amount of unique reset connections, amount of incomplete connections and complete connections.
		- The mean,max and minimum values of the packets sent, the time duration, the RTT times and the Window sizes of all complete connections.


--- FUNCTIONS:
	
	- calc_RTT: Calcultes the RTT values of packets sent by source.
	- calc_RTT_dst: Calcultes the RTT values of packets sent by source.

	- check_conn: Takes a packet and associates it with the proper connection, calls calc_RTT and calc_RTT_dst when appropriate, and calculates the statistics.
	
	- ReadTraceFile: Seperates the TCP header and Data from the IP and Ethernet headers. Passes the TCP header to check_conn, if the packet has a syn, fin, or rst flag it adds it to the connections total syn,fin or rst values.

	- main: Opens the cap file, extracts the packets, passes it to ReadTraceFile and prints out the statistics.

--- LIBRARY'S IMPLEMENTED:

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


