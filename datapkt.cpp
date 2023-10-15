#include "datapkt.h"
#include <QMetaType>

DataPkt::DataPkt()
{
    qRegisterMetaType<DataPkt>("DataPkt");

    this->timestamp = "";
    this->data_len = 0;
    this->pkt_type = 0;

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
    case 1: return "ARP";
    case 2: return "ICMP";
    case 3: return "TCP";
    case 4: return "UDP";
    case 5: return "DNS";
    case 6: return "TLS";
    case 7: return "SSL";
    default: return "";
    }
}

void DataPkt::setPktType(int new_pkt_type)
{
    this->pkt_type = new_pkt_type;
}

QString DataPkt::HextoS(char *num,int size){ //hex-num to string
    QString res = "";
    for (int i=0;i<size;i++) {
        char h = num[i] >> 4;
        h = (h > 0x09) ? h - 0x09 + 0x41 : h + 0x30;
        res.append(h);
        char l = num[i] & 0x0f;
        l = (l > 0x09) ? l - 0x09 + 0x41 : l + 0x30;
        res.append(l);
    }
    return res;
}
