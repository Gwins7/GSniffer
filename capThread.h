#ifndef CAPTHREAD_H
#define CAPTHREAD_H
#include <QThread>
#include "pcap.h"

class capThread:public QThread
{
    Q_OBJECT
public:
    capThread(void);
    void setPcapPtr(pcap_t *ptr);
    void setRunningStatus(bool status);
    void run() override;
private:
    bool isRunning;
    pcap_t *pcap_ptr;
    struct pcap_pkthdr *pkt_hdr;
    const u_char *pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char time_string[16];
};

#endif // CAPTHREAD_H
