#include "capThread.h"
#include "pktfmt.h"
#include "datapkt.h"
#include <QDebug>

capThread::capThread(void)
{
    setRunningStatus(false);
}

void capThread::setPcapPtr(pcap_t *ptr){
    this->pcap_ptr = ptr;
}

void capThread::setRunningStatus(bool status){
    this->isRunning = status;
}

void capThread::run(){
    while (isRunning){
        int res = pcap_next_ex(pcap_ptr,&pcap_pkt_hdr,&pcap_pkt_data);
        if (!res) continue;

        //now you have got a pkt

        //time handling
        loc_time_sec = pcap_pkt_hdr->ts.tv_sec;
        localtime_s(&loc_time, &loc_time_sec);//convert
        strftime(time_str,sizeof(time_str),"%H:%M:%S",&loc_time);
        QString info = "";
        int pkt_type = HandleEthPkt(pcap_pkt_data,info);
        if (pkt_type) {
            //pkt_type != 0
            DataPkt pkt;
            int len = pcap_pkt_hdr->len;
            pkt.AllocPktContent(pcap_pkt_data,len);
            pkt.setInfo(info);
            pkt.setDataLen(len);
            pkt.setTimestamp(time_str);
            pkt.setPktType(pkt_type);

            emit SendMsg(pkt);  //send pkt to main thread
        }
    }
}

int capThread::HandleEthPkt(const u_char *pkt_content, QString &info){
    // ret val: pkt_type
    eth_hdr_t *ether_hdr = (eth_hdr_t *)pkt_content;
    u_short content_type = ntohs(ether_hdr->type);
    switch(content_type) {
        case 0x0800:{ //ipv4
            int ip_pld_len = 0;
            int ip_protocol = HandleIpPkt(pkt_content,ip_pld_len);
            switch(ip_protocol){
                case 1:{ //ICMP
                    return HandleIcmpPkt(pkt_content,info);
                }
                case 6:{ //TCP
                    return HandleTcpPkt(pkt_content,info,ip_pld_len);
                }
                case 17:{//UDP
                    return HandleUdpPkt(pkt_content,info);
                }
                default:return TYPE_IP_OTHER;
            }
        }
        case 0x0806:{ //arp
            return HandleArpPkt(pkt_content,info);
        }
        default:return TYPE_ETH_OTHER;
    }
    return 0; // you shouldn't be here
}

int capThread::HandleIpPkt(const u_char *pkt_content, int &ip_pld_len){
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(pkt_content + ETH_HDR_LEN);
    ip_pld_len = (ntohs(ip_hdr->tot_len) - ((ip_hdr->ver_n_hdrlen & 0x0f) << 2));
    return ip_hdr->protocol;
}

int capThread::HandleTcpPkt(const u_char *pkt_content, QString &info, int ip_pld_len){
    tcp_hdr_t *tcp_hdr = (tcp_hdr_t *)(pkt_content + ETH_HDR_LEN + IP_HDR_LEN);
    u_short src_port = ntohs(tcp_hdr->src_port);
    u_short dst_port = ntohs(tcp_hdr->dst_port);

    int tcp_hdr_len = (tcp_hdr->hdr_len & 0xf0) >> 2; // >> 4 << 2
    int tcp_pld_len = ip_pld_len - tcp_hdr_len;

    //pkt type_info in detail
    QString proSend = "";
    QString proRecv = "";
    switch (src_port)
    {
    case 443:{
        proSend = "(https)";
        break;
        }
    case 80:{
        proSend = "(http)";
        break;
    }
    default: break;
    }
    switch (dst_port)
    {
    case 443:{
        proRecv = "(https)";
        break;
    }
    case 80:{
        proRecv = "(http)";
        break;
    }
    default: break;
    }
    info += QString::number(src_port) + proSend + "->" + QString::number(dst_port) + proRecv;

    // flags
    QString flag_info = "";
    // - - URG ACK PSH RST SYN FIN
    if (tcp_hdr->flags & 0x01) flag_info += "FIN,";
    if (tcp_hdr->flags & 0x02) flag_info += "SYN,";
    if (tcp_hdr->flags & 0x04) flag_info += "RST,";
    if (tcp_hdr->flags & 0x08) flag_info += "PSH,";
    if (tcp_hdr->flags & 0x10) flag_info += "ACK,";
    if (tcp_hdr->flags & 0x20) flag_info += "URG,";
    if (flag_info != ""){
        flag_info = flag_info.left(flag_info.length() - 1); // remove the last ","
        info += " [" + flag_info + "] ";
    }

    // seq / ack / window
    u_int tcp_seq = ntohl(tcp_hdr->seq);
    u_int tcp_ack = ntohl(tcp_hdr->ack);
    u_int tcp_window = ntohs(tcp_hdr->window_size);
    info += "Seq=" + QString::number(tcp_seq) + " " +
            "Ack=" + QString::number(tcp_ack) + " " +
            "Window = " + QString::number(tcp_window) + " " +
            "Len = " + QString::number(tcp_pld_len);

    return TYPE_TCP;
}

int capThread::HandleUdpPkt(const u_char *pkt_content, QString &info){
    udp_hdr_t *udp_hdr = (udp_hdr_t *)(pkt_content + ETH_HDR_LEN + IP_HDR_LEN);
    u_short src_port = ntohs(udp_hdr->src_port);
    u_short dst_port = ntohs(udp_hdr->dst_port);

    if (src_port == 53 || dst_port == 53) {
        info += "DNS; ";
    }
    //udp_info
    QString udp_info = QString::number(src_port) + "->" + QString::number(dst_port) + " " +
                        "len = " + QString::number(ntohs(udp_hdr->data_len));
    info += udp_info;
    return TYPE_UDP;
}

int capThread::HandleArpPkt(const u_char *pkt_content, QString &info){
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(pkt_content + ETH_HDR_LEN); // ip level

    u_short arp_op = ntohs(arp_hdr->op_code);

    //convert addr to QString
    QString arp_src_ip_addr =  ConvertIpAddr(arp_hdr->src_ip_addr);
    QString arp_dst_ip_addr =  ConvertIpAddr(arp_hdr->dst_ip_addr);
    QString arp_src_eth_addr = ConvertEthAddr(arp_hdr->src_eth_addr);
//    QString arp_dst_eth_addr = getEthAddr(arp_hdr->dst_eth_addr);

    QString arp_info;
    if(arp_op == 1) arp_info = "Who has " + arp_dst_ip_addr + "? Tell " + arp_src_ip_addr; // query
    else if (arp_op == 2) arp_info = arp_src_ip_addr + " is at " + arp_src_eth_addr; // response
    else arp_info = "other ARP packet, op = " + QString::number(arp_op);
    info += arp_info;
    return TYPE_ARP;
}

int capThread::HandleIcmpPkt(const u_char *pkt_content, QString &info){
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) (pkt_content + ETH_HDR_LEN + IP_HDR_LEN);
    u_char icmp_type = icmp_hdr->type;
    u_char icmp_code = icmp_hdr->code;
    QString res = "";
    switch (icmp_type) {
    case 0:{
        if(!icmp_code)
            res = "Echo response (ping)";
        break;
    }
    case 3:{
        switch (icmp_code) {
            case 0:{
                res = "Network unreachable";
                break;
            }
            case 1:{
                res = "Host unreachable";
                break;
            }
            case 2:{
                res = "Protocol unreachable";
                break;
            }
            case 3:{
                res = "Port unreachable";
                break;
            }
            case 4:{
                res = "Fragmentation is required, but DF is set";
                break;
            }
            case 5:{
                res = "Source route selection failed";
                break;
            }
            case 6:{
                res = "Unknown target network";
                break;
            }
            default:break;
        }
        break;
    }
    case 4:{
        res = "Source station suppression [congestion control]";
        break;
    }
    case 5:{
        res = "Relocation";
        break;
    }
    case 8:{
        if(!icmp_code)
            res = "Echo request (ping)";
        break;
    }
    default:break;
    }

    info += res;
    return TYPE_ICMP;
}


QString capThread::HextoS(u_char *num,int size){ //hex-num to string
    QString res = "";
    for (int i=0;i<size;i++) {
        char h = num[i] >> 4;
        h = (h > 0x09) ? h - 0x0a + 0x41 : h + 0x30;
        res.append(h);
        char l = num[i] & 0x0f;
        l = (l > 0x09) ? l - 0x0a + 0x41 : l + 0x30;
        res.append(l);
    }
    return res;
}

QString capThread::ConvertEthAddr(u_char *addr){
    QString res = HextoS(addr,1) + ":" +
                  HextoS((addr+1),1) + ":" +
                  HextoS((addr+2),1) + ":" +
                  HextoS((addr+3),1) + ":" +
                  HextoS((addr+4),1) + ":" +
                  HextoS((addr+5),1);
    return res;
}

QString capThread::ConvertIpAddr(u_char *addr){
    QString res = QString::number(*addr) + "." +
                  QString::number(*(addr+1)) + "." +
                  QString::number(*(addr+2)) + "." +
                  QString::number(*(addr+3));
    return res;
}

