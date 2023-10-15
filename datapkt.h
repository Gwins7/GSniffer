#ifndef DATAPKT_H
#define DATAPKT_H

#include "pktfmt.h"
#include <QString>

class DataPkt
{
public:
    const u_char *pkt_content;
    DataPkt();
    QString getDataLen() const;
    void setDataLen(u_int newDataLen);
    QString getTimestamp() const;
    void setTimestamp(const QString &new_timestamp);
    QString getInfo() const;
    void setInfo(const QString &new_info);
    QString getPktType() const;
    void setPktType(int new_pkt_type);

private:
    u_int data_len;
    QString timestamp;
    QString info;
    int pkt_type;

protected:
    static QString HextoS (char *num,int size);
};

#endif // DATAPKT_H
