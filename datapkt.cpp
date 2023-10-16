#include "datapkt.h"
#include <QMetaType>
#include "winsock2.h"
DataPkt::DataPkt()
{
    qRegisterMetaType<DataPkt>("DataPkt");

    this->timestamp = "";
    this->data_len = 0;
    this->pkt_type = 0;

}

void DataPkt::FreePktContent(){
    free(this->pkt_content);
    this->pkt_content = NULL;
}

void DataPkt::AllocPktContent(
    const u_char *pkt_content,
    int size){
    this->pkt_content = (u_char *)malloc(size);
    memcpy((char*)(this->pkt_content),pkt_content,size);
}

u_char *DataPkt::getPktContent(){
    return this->pkt_content;
}

u_int DataPkt::getDataLen() const
{
    return this->data_len;
}

void DataPkt::setDataLen(u_int new_data_len)
{
    this->data_len = new_data_len;
}

QString DataPkt::getTimestamp() const
{
    return this->timestamp;
}

void DataPkt::setTimestamp(const QString &new_timestamp)
{
    this->timestamp = new_timestamp;
}

QString DataPkt::getInfo() const
{
    return this->info;
}

void DataPkt::setInfo(const QString &new_info)
{
    this->info = new_info;
}

QString DataPkt::getPktType() const
{
    switch(this->pkt_type){
    case TYPE_ARP: return "ARP";
    case TYPE_ICMP: return "ICMP";
    case TYPE_TCP: return "TCP";
    case TYPE_UDP: return "UDP";
    default: return "";
    }
}

void DataPkt::setPktType(int new_pkt_type)
{
    this->pkt_type = new_pkt_type;
}

QString DataPkt::HextoS(u_char *num,int size){ //hex-num to string
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

QString DataPkt::ConvertEthAddr(u_char *addr){
    QString res = HextoS(addr,1) + ":" +
                  HextoS((addr+1),1) + ":" +
                  HextoS((addr+2),1) + ":" +
                  HextoS((addr+3),1) + ":" +
                  HextoS((addr+4),1) + ":" +
                  HextoS((addr+5),1);
    return res;
}

QString DataPkt::ConvertIpAddr(u_char *addr){
    QString res = QString::number(*addr) + "." +
                  QString::number(*(addr+1)) + "." +
                  QString::number(*(addr+2)) + "." +
                  QString::number(*(addr+3));
    return res;
}

// get info for tree widget and browser display

QString DataPkt::getEthInfo(int info_type){
    eth_hdr_t *eth_hdr = (eth_hdr_t *)(pkt_content);
    QString res = "";
    switch (info_type){
        case INFO_ETH_ADDR_SRC:
        case INFO_ETH_ADDR_DST:{
            res = ConvertEthAddr(info_type == INFO_ETH_ADDR_DST ? eth_hdr->mac_dst : eth_hdr->mac_src);
            if (res == "FF:FF:FF:FF:FF:FF") res = "Broadcast";
            break;
        }
        case INFO_ETH_TYPE:{
            u_short type = ntohs(eth_hdr->type);
            if (type == 0x0800) res = "IPv4 (0x0800) ";
            else if (type == 0x0806) res = "ARP (0x0806) ";
            else res = "Others (0x" + QString::number(type,16) + ")";
            break;
        }
        default:break;
    }
    return res;
}

QString DataPkt::getIpInfo(int info_type){
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(pkt_content + ETH_HDR_LEN);
    QString res = "";
    switch (info_type){
        case INFO_IP_ADDR_SRC:
        case INFO_IP_ADDR_DST:{
            res = ConvertIpAddr((u_char *)&(info_type ==
                    INFO_IP_ADDR_DST ? ip_hdr->dst_addr : ip_hdr->src_addr));
            break;
        }
        case INFO_IP_VERSION:{
            res = QString::number(ip_hdr->ver_n_hdrlen >> 4);
            break;
        }
        case INFO_IP_HDR_LEN:{
            res = QString::number(ip_hdr->ver_n_hdrlen & 0X0f << 2);
            break;
        }
        case INFO_IP_TOS:{
            res = "0x" + QString::number((u_int)ip_hdr->TOS,16);
            break;
        }
        case INFO_IP_TOT_LEN:{
            res = QString::number(ntohs(ip_hdr->tot_len));
            break;
        }
        case INFO_IP_IDENT: {
            res = "0x" + QString::number((u_int)ntohs(ip_hdr->ident),16);
            break;
        }
        case INFO_IP_FLAGS:{
            res = "0x" + QString::number((u_int)ntohs(ip_hdr->flag_n_offset >> 5),16);
            QString flags_info = "";
            if (ip_hdr->flag_n_offset >> 5 & 0x1) flags_info += "Reversed Bit,";
            if (ip_hdr->flag_n_offset >> 5 & 0x2) flags_info += "Don't Fragment,";
            if (ip_hdr->flag_n_offset >> 5 & 0x4) flags_info += "More Fragments,";
            if (flags_info!=""){
                flags_info = flags_info.left(flags_info.length() - 1); // remove the last ","
                res += " (" + flags_info + ")";
            }
            break;
        }
        case INFO_IP_OFFSET:{
            res = "0x" + QString::number((u_int)ntohs(ip_hdr->flag_n_offset & 0x1f << 3),16);
            break;
        }
        case INFO_IP_TTL:{
            res = QString::number(ip_hdr->ttl);
            break;
        }
        case INFO_IP_PROTOCOL:{
            res = QString::number(ip_hdr->protocol);
            if (ip_hdr->protocol == 4) res += " (TCP)";
            else if (ip_hdr->protocol == 17) res += " (UDP)";
            break;
        }
        case INFO_IP_CHECKSUM:{
            res = "0x" + QString::number((u_int)ntohs(ip_hdr->checksum),16);
            break;
        }
        default:break;
    }

    return res;
}

QString DataPkt::getArpInfo(int info_type){
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(pkt_content + ETH_HDR_LEN);
    QString res = "";
    switch (info_type){
        case INFO_ARP_HW_TYPE:{
            if (ntohs(arp_hdr->hardware_type == 1)) res = "Ethernet";
            else res = "Others";
            res += " (" + QString::number(ntohs(arp_hdr->hardware_type)) + ")";
            break;
        }
        case INFO_ARP_PROTOCOL_TYPE:{
            if (ntohs(arp_hdr->protocol_type) == 0x0800) res = "IPv4";
            else res = "Others";
            res += " (0x" + QString::number((u_int)ntohs(arp_hdr->protocol_type),16) + ")";
            break;
        }
        case INFO_ARP_ETH_LEN:{
            res = QString::number(arp_hdr->eth_len);
            break;
        }
        case INFO_ARP_IP_LEN:{
            res = QString::number(arp_hdr->ip_len);
            break;
        }
        case INFO_ARP_OP_CODE:{
            if (ntohs(arp_hdr->op_code) == 1) res = "request";
            else if (ntohs(arp_hdr->op_code) == 2) res = "response";
            else res = "others";
            res += " (" + QString::number(ntohs(arp_hdr->op_code)) + ")";
            break;
        }
        case INFO_ARP_MAC_SRC:{
            res = ConvertEthAddr(arp_hdr->src_eth_addr);
            break;
        }
        case INFO_ARP_MAC_DST:{
            res = ConvertEthAddr(arp_hdr->dst_eth_addr);
            break;
        }
        case INFO_ARP_IP_SRC:{
            res = ConvertIpAddr(arp_hdr->src_ip_addr);
            break;
        }
        case INFO_ARP_IP_DST:{
            res = ConvertIpAddr(arp_hdr->dst_ip_addr);
            break;
        }
        default:break;
    }
    return res;
}

QString DataPkt::getTcpInfo(int info_type){
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(pkt_content + ETH_HDR_LEN);
    tcp_hdr_t *tcp_hdr = (tcp_hdr_t *)(pkt_content + ETH_HDR_LEN + IP_HDR_LEN);

    QString res = "";
    switch (info_type){
        case INFO_TCP_SRC_PORT:{
            res = QString::number(ntohs(tcp_hdr->src_port));
            break;
        }
        case INFO_TCP_DST_PORT:{
            res = QString::number(ntohs(tcp_hdr->dst_port));
            break;
        }
        case INFO_TCP_SEQ:{
            res = QString::number((u_int)ntohl(tcp_hdr->seq));
            break;
        }
        case INFO_TCP_ACK:{
            res = QString::number((u_int)ntohl(tcp_hdr->ack));
            break;
        }
        case INFO_TCP_HDR_LEN:{
            res = QString::number((tcp_hdr->hdr_len & 0xf0) >> 2);
            break;
        }
        case INFO_TCP_FLAGS:{
            res = "0x" + QString::number((u_int)(tcp_hdr->flags & 0x3f),16);
            QString flag_info = "";
            if (tcp_hdr->flags & 0x01) flag_info += "FIN,";
            if (tcp_hdr->flags & 0x02) flag_info += "SYN,";
            if (tcp_hdr->flags & 0x04) flag_info += "RST,";
            if (tcp_hdr->flags & 0x08) flag_info += "PSH,";
            if (tcp_hdr->flags & 0x10) flag_info += "ACK,";
            if (tcp_hdr->flags & 0x20) flag_info += "URG,";
            if (flag_info != ""){
            flag_info = flag_info.left(flag_info.length() - 1); // remove the last ","
            res += " (" + flag_info + ")";
            }
            break;
        }
        case INFO_TCP_WINDOW_SIZE:{
            res = QString::number((u_int)ntohs(tcp_hdr->window_size));
            break;
        }
        case INFO_TCP_CHECKSUM:{
            res = "0x" + QString::number((u_int)ntohs(tcp_hdr->checksum),16);
            break;
        }
        case INFO_TCP_URG:{
            res = "0x" + QString::number(ntohs(tcp_hdr->urg));
            break;
        }
        case INFO_TCP_PLD_LEN:{ //SPECIAL: CALCULATE
            int tcp_pld_len = ntohs(ip_hdr->tot_len) - ((ip_hdr->ver_n_hdrlen & 0x0f) << 2) - ((tcp_hdr->hdr_len & 0xf0) >> 2);
            res = QString::number(tcp_pld_len);
        }
        default:break;
    }
    return res;
}
QString DataPkt::getUdpInfo(int info_type){
    udp_hdr_t *udp_hdr = (udp_hdr_t *)(pkt_content + ETH_HDR_LEN + IP_HDR_LEN);
    QString res = "";
    switch (info_type){
        case INFO_UDP_SRC_PORT:{
            res = QString::number(ntohs(udp_hdr->src_port));
            break;
        }
        case INFO_UDP_DST_PORT:{
            res = QString::number(ntohs(udp_hdr->dst_port));
            break;
        }
        case INFO_UDP_DATA_LEN:{
            res = QString::number(ntohs(udp_hdr->data_len));
            break;
        }
        case INFO_UDP_CHECKSUM:{
            res = "0x" + QString::number((u_int)ntohs(udp_hdr->checksum),16);
            break;
        }
        case INFO_UDP_PLD_LEN:{
            res = QString::number(ntohs(udp_hdr->data_len)-8);
        }
        default:break;
    }
    return res;
}
QString DataPkt::getIcmpInfo(int info_type){
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)(pkt_content + ETH_HDR_LEN + IP_HDR_LEN);
    QString res = "";
    switch (info_type){
        case INFO_ICMP_TYPE:{
            switch (icmp_hdr->type){
                case 0:{
                    res = "echo response";
                }
                case 3:{
                    res = "unreachable";
                }
                case 4:{
                    res = "suppression";
                }
                case 5:{
                    res = "relocation";
                }
                case 8:{
                    res = "echo request";
                }
                default:{
                    res = "others";
                    break;
                }
            }
            res += " (" + QString::number(icmp_hdr->type) + ")";
            break;
        }
        case INFO_ICMP_CODE:{
            res = QString::number(icmp_hdr->code);
            break;
        }
        case INFO_ICMP_CHECKSUM:{
            res = "0x" + QString::number((u_int)ntohs(icmp_hdr->checksum),16);
            break;
        }
        case INFO_ICMP_IDENT:{
            res = QString::number(ntohs(icmp_hdr->ident));
            break;
        }
        case INFO_ICMP_SEQ:{
            res = QString::number(ntohs(icmp_hdr->seq));
            break;
        }
        default:break;
    }
    return res;
}

