#include "capThread.h"
#include "pktfmt.h"
#include "datapkt.h"
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
        int res = pcap_next_ex(pcap_ptr,&pcap_pkt_hdr,&pcap_pkt_data);
        if (!res) continue;

        //now you have got a pkt

        //time handling
        loc_time_sec = pcap_pkt_hdr->ts.tv_sec;
        localtime_s(&loc_time, &loc_time_sec);//convert
        strftime(time_str,sizeof(time_str),"%H:%M:%S",&loc_time);
        QString info = "";
        int pkt_type = HandleEthPkt(pcap_pkt_data,info);
        if (pkt_type) {
            //pkt_type != 0
            DataPkt pkt;
            int len = pcap_pkt_hdr->len;
            pkt.setInfo(info);
            pkt.setDataLen(len);
            pkt.setTimestamp(time_str);
            emit SendMsg(pkt);  //send pkt to main thread
        }
    }
}

int capThread::HandleEthPkt(const u_char *pkt_content, QString &info){
    // ret val: pkt_type
    eth_hdr_t *ether_hdr = (eth_hdr_t *)pkt_content;
    u_short content_type = ntohs(ether_hdr->type);
    switch(content_type) {
        case 0x0800:{ //ipv4
        info = "ipv4";
            break;
        }
        case 0x0806:{ //arp
            info = "arp";
            break;
        }
        default:return 0;
    }
    return (int)content_type;
}
