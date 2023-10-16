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

QString DataPkt::getDataLen() const
{
    return QString::number(this->data_len);
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
    case TYPE_DNS: return "DNS";
    case TYPE_TLS: return "TLS";
    case TYPE_SSL: return "SSL";
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

QString DataPkt::getEthAddr(u_char *addr){
    QString res = HextoS(addr,1) + ":" +
                  HextoS((addr+1),1) + ":" +
                  HextoS((addr+2),1) + ":" +
                  HextoS((addr+3),1) + ":" +
                  HextoS((addr+4),1) + ":" +
                  HextoS((addr+5),1);
    return res;
}

QString DataPkt::getIpAddr(u_char *addr){
    QString res = QString::number(*addr) + "." +
                  QString::number(*(addr+1)) + "." +
                  QString::number(*(addr+2)) + "." +
                  QString::number(*(addr+3));
    return res;
}

QString DataPkt::getEthSrc(){
    eth_hdr_t *eth_hdr = (eth_hdr_t *)(pkt_content);
    QString res = getEthAddr(eth_hdr->mac_src);
    if (res == "FF:FF:FF:FF:FF:FF") res = "Broadcast";
    return res;
}

QString DataPkt::getEthDst(){
    eth_hdr_t *eth_hdr = (eth_hdr_t *)(pkt_content);
    QString res = getEthAddr(eth_hdr->mac_dst);
    if (res == "FF:FF:FF:FF:FF:FF") res = "Broadcast";
    return res;
}

QString DataPkt::getIpSrc(){
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(pkt_content + ETH_HDR_LEN);
    QString res = getIpAddr((u_char *)&(ip_hdr->src_addr));
    return res;
}
QString DataPkt::getIpDst(){
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(pkt_content + ETH_HDR_LEN);
    QString res = getIpAddr((u_char *)&(ip_hdr->dst_addr));
    return res;
}
