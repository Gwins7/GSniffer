#include "capThread.h"
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
        int res = pcap_next_ex(pcap_ptr,&pkt_hdr,&pkt_data);
        if (!res) continue;

        //now you have got a pkt

        //time handling
        local_time_sec = pkt_hdr->ts.tv_sec;
        localtime_s(&local_time, &local_time_sec);//convert
        strftime(time_string,sizeof(time_string),"%H:%M:%S",&local_time);
        qDebug()<<time_string;
    }
}
