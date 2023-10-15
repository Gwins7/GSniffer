#ifndef CAPTHREAD_H
#define CAPTHREAD_H
#include <QThread>
#include "pcap.h"
#include "datapkt.h"

class capThread:public QThread
{
    Q_OBJECT

public:
    capThread(void);
    void setPcapPtr(pcap_t *ptr);
    void setRunningStatus(bool status);
    void run() override;

    int HandleEthPkt(const u_char *pkt_content, QString &info);

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
};

#endif // CAPTHREAD_H
