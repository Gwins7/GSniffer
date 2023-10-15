#ifndef CAPTHREAD_H
#define CAPTHREAD_H
#include <QThread>
#include "pcap.h"
#include "datapkt.h"

class capThread:public QThread
{
    Q_OBJECT

public:
    capThread();
    void setPcapPtr(pcap_t *ptr);
    void setRunningStatus(bool status);
    void run() override;

    int HandleEthPkt(const u_char *pkt_content, QString &info);
    int HandleIpPkt (const u_char *pkt_content, int &ip_pld_len);
    int HandleTcpPkt(const u_char *pkt_content, QString &info, int ip_pld_len);
    int HandleUdpPkt(const u_char *pkt_content, QString &info);
    QString HandleArpPkt(const u_char *pkt_content);

signals: // send pkt_data across the threads
    void SendMsg(DataPkt pkt);

private:
    bool isRunning;
    pcap_t *pcap_ptr;
    struct pcap_pkthdr *pcap_pkt_hdr;
    const u_char *pcap_pkt_data;
    time_t loc_time_sec;
    struct tm loc_time;
    char time_str[16];

protected:
    QString getEthAddr(u_char *addr);
    QString getIpAddr(u_char *addr);
    static QString HextoS (u_char *num,int size);
};

#endif // CAPTHREAD_H
