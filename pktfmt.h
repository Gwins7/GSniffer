#ifndef PKTFMT_H
#define PKTFMT_H

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

// Ethernet header
/*
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/

typedef struct eth_hdr{ //14 bytes
    u_char mac_dst[6];
    u_char mac_src[6];
    u_short type;
} eth_hdr_t;

// ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           |R|D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocol  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/

typedef struct ip_hdr{ //20 bytes
    u_char ver_n_headlen;
    u_char TOS;
    u_short tot_len;
    u_short ident;
    u_short flag_n_offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_addr;
    u_int dst_addr;
} ip_hdr_t;

// tcp header
/*
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/

typedef struct tcp_hdr{ //20 bytes
    u_short src_port;
    u_short dst_port;
    u_int seq;
    u_int ack;
    u_char hdr_len;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urg;
} tcp_hdr_t;

// udp header
/*
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/

typedef struct udp_hdr{ //8 bytes
    u_short src_port;
    u_short dst_port;
    u_short data_len;
    u_short checksum;

} udp_hdr_t;

// icmp header
/*
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct icmp_hdr{ //>=8 bytes
    u_char type;
    u_char code;
    u_short checksum;
    u_short ident;
    u_short seq;
} icmp_hdr_t;

//arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct arp_hdr{   // 28 bytes
    u_short hardware_type;
    u_short protocol_type;
    u_char eth_len;
    u_char ip_len;
    u_short op_code;

    u_char src_eth_addr[6];
    u_char src_ip_addr[4];
    u_char dst_eth_addr[6];
    u_char dst_ip_addr[4];

} arp_hdr_t;

// dns
/*
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/
typedef struct dns_hdr{  //12 bytes
    u_short ident;
    u_short flags;
    u_short question;
    u_short answer;
    u_short authority;
    u_short additional;
} dns_hdr_t;

// dns question
typedef struct dns_question{
    // char* name;          // Non-fixed
    u_short query_type;     // 2 byte
    u_short query_class;    // 2 byte
} dns_question_t;

typedef struct dns_answer{
    // char* name          // Non-fixed
    u_short answer_type;   // 2 byte
    u_short answer_class;  // 2 byte
    u_int TTL;             // 4 byte
    u_short data_len;    // 2 byte
    //char* name           // Non-fixed
} dns_answer_t;

#endif // PKTFMT_H
