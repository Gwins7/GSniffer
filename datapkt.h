#ifndef DATAPKT_H
#define DATAPKT_H

#include "pktfmt.h"
#include "macro.h"
#include <QString>

class DataPkt
{
public:

    DataPkt();
    u_char *getPktContent();
    void FreePktContent();
    void AllocPktContent(const u_char *pkt_content, int size);
    u_int getDataLen() const;
    void setDataLen(u_int newDataLen);
    QString getTimestamp() const;
    void setTimestamp(const QString &new_timestamp);
    QString getInfo() const;
    void setInfo(const QString &new_info);
    QString getPktType() const;
    void setPktType(int new_pkt_type);

    QString getEthInfo(int info_type);
    QString getIpInfo(int info_type);
    QString getArpInfo(int info_type);
    QString getTcpInfo(int info_type);
    QString getUdpInfo(int info_type);
    QString getIcmpInfo(int info_type);

private:
    u_char *pkt_content;
    u_int data_len;
    QString timestamp;
    QString info;
    int pkt_type;

protected:
    QString ConvertEthAddr(u_char *addr);
    QString ConvertIpAddr(u_char *addr);
    static QString HextoS (u_char *num,int size);
};

#endif // DATAPKT_H
