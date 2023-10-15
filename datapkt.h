#ifndef DATAPKT_H
#define DATAPKT_H

#include "pktfmt.h"
#include <QString>

#define TYPE_ARP 1
#define TYPE_ICMP 2
#define TYPE_TCP 3
#define TYPE_UDP 4
#define TYPE_DNS 5
#define TYPE_TLS 6
#define TYPE_SSL 7

class DataPkt
{
public:

    DataPkt();
    u_char *getPktContent();
    void FreePktContent();
    void AllocPktContent(const u_char *pkt_content, int size);
    QString getDataLen() const;
    void setDataLen(u_int newDataLen);
    QString getTimestamp() const;
    void setTimestamp(const QString &new_timestamp);
    QString getInfo() const;
    void setInfo(const QString &new_info);
    QString getPktType() const;
    void setPktType(int new_pkt_type);

    QString getEthSrc();
    QString getEthDst();
    QString getIpSrc();
    QString getIpDst();

private:
    u_char *pkt_content;
    u_int data_len;
    QString timestamp;
    QString info;
    int pkt_type;

protected:
    QString getEthAddr(u_char *addr);
    QString getIpAddr(u_char *addr);
    static QString HextoS (u_char *num,int size);
};

#endif // DATAPKT_H
