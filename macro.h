#ifndef MACRO_H
#define MACRO_H

//hdr len
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define TCP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define ICMP_HDR_LEN 8
#define ARP_HDR_LEN 28

//pkt type
#define TYPE_ARP 1
#define TYPE_ICMP 2
#define TYPE_TCP 3
#define TYPE_UDP 4
#define TYPE_ETH_OTHER 5
#define TYPE_IP_OTHER 6
//eth info
#define INFO_ETH_ADDR_SRC 0
#define INFO_ETH_ADDR_DST 1
#define INFO_ETH_TYPE 2

//ip info
#define INFO_IP_ADDR_SRC 0
#define INFO_IP_ADDR_DST 1
#define INFO_IP_VERSION 2
#define INFO_IP_HDR_LEN 3
#define INFO_IP_TOS 4
#define INFO_IP_TOT_LEN 5
#define INFO_IP_IDENT 6
#define INFO_IP_FLAGS 7
#define INFO_IP_OFFSET 8
#define INFO_IP_TTL 9
#define INFO_IP_PROTOCOL 10
#define INFO_IP_CHECKSUM 11

//arp info
#define INFO_ARP_HW_TYPE 0
#define INFO_ARP_PROTOCOL_TYPE 1
#define INFO_ARP_ETH_LEN 2
#define INFO_ARP_IP_LEN 3
#define INFO_ARP_OP_CODE 4
#define INFO_ARP_MAC_SRC 5
#define INFO_ARP_MAC_DST 6
#define INFO_ARP_IP_SRC 7
#define INFO_ARP_IP_DST 8

//tcp info
#define INFO_TCP_SRC_PORT 0
#define INFO_TCP_DST_PORT 1
#define INFO_TCP_SEQ 2
#define INFO_TCP_ACK 3
#define INFO_TCP_HDR_LEN 4
#define INFO_TCP_FLAGS 5
#define INFO_TCP_WINDOW_SIZE 6
#define INFO_TCP_CHECKSUM 7
#define INFO_TCP_URG 8

#define INFO_TCP_PLD_LEN 9

//udp info
#define INFO_UDP_SRC_PORT 0
#define INFO_UDP_DST_PORT 1
#define INFO_UDP_DATA_LEN 2
#define INFO_UDP_CHECKSUM 3

#define INFO_UDP_PLD_LEN 4

//icmp info
#define INFO_ICMP_TYPE 0
#define INFO_ICMP_CODE 1
#define INFO_ICMP_CHECKSUM 2
#define INFO_ICMP_IDENT 3
#define INFO_ICMP_SEQ 4

#endif // MACRO_H
