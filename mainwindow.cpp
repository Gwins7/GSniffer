#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "capThread.h"
#include "ROD.h"
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    // ui init
    ui->setupUi(this);
    ListNIC(); // display NIC in NICBox
    statusBar()->showMessage("Welcome to GSniffer!");

    // toolbar
    ui->toolBar->addAction(ui->actionrunstop);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->setMovable(false);

    //pkttable
    ui->PktTable->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = {"No.",
                         "Time",
                         "Source",
                         "Destination",
                         "Protocol",
                         "Length",
                         "Info"};
    ui->PktTable->setColumnCount(7);
    ui->PktTable->setHorizontalHeaderLabels(title);
    ui->PktTable->setColumnWidth(0,50);
    ui->PktTable->setColumnWidth(1,100);
    ui->PktTable->setColumnWidth(2,150);
    ui->PktTable->setColumnWidth(3,150);
    ui->PktTable->setColumnWidth(4,100);
    ui->PktTable->setColumnWidth(5,100);
    ui->PktTable->setColumnWidth(6,750);

    ui->PktTable->setShowGrid(false); // disable column separate line display
    ui->PktTable->verticalHeader()->setVisible(false); // disable table No.
    ui->PktTable->setSelectionBehavior(QAbstractItemView::SelectRows); // select the whole row
    ui->PktTable->setItemDelegate(new ReadOnlyDelegate); //can't edit the pkttable

    ui->PktTree->setHeaderHidden(true);

    // function init
    cur_dev = 0;
    capThread *cap_thread = new capThread;
    cap_status = false;

    connect(ui->actionrunstop,&QAction::triggered,this,[=]{ // set action on run/stop
        cap_status = !cap_status; // on - off
        if (cap_status) { // on

            //clear previous content
            ui->PktTable->clearContents();
            ui->PktTable->setRowCount(0);
            pkt_count = 0;
            row_chosen = -1;
            ui->PktTree->clear();
            ui->PktBrowser->clear();
            for (int i=0; i<pkt_vec.size();i++){
                this->pkt_vec[i].FreePktContent();
            }

            QVector<DataPkt>().swap(pkt_vec); //free DataPkt

            if (OpenCurDev() != -1){
                // new capture init
                cap_thread->setRunningStatus(true);
                cap_thread->setPcapPtr(pcap_ptr);
                cap_thread->start();
                ui->actionrunstop->setText("stop");
                ui->NICBox->setEnabled(false);
            }
            else {
                cap_status = !cap_status;
                statusBar()->showMessage("You have chosen an invalid NIC!");
            }
        }
        else {
            // stop capture
            cap_thread->setRunningStatus(false);
            cap_thread->quit();
            cap_thread->wait(); //wait to release resources
            ui->actionrunstop->setText("run");
            ui->NICBox->setEnabled(true);
            pcap_close(pcap_ptr);
            pcap_ptr = NULL;
        }
    });

    connect(ui->actionclear,&QAction::triggered,this,[=]{ //set action on clear
        ui->PktTable->clearContents();
        ui->PktTable->setRowCount(0);
        pkt_count = 0;
        row_chosen = -1;
        ui->PktTree->clear();
        ui->PktBrowser->clear();
    });

    // pkt: capThread::SendMsg -> MainWindow::HandleMsg
    connect(cap_thread,&capThread::SendMsg,this,&MainWindow::HandleMsg);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::ListNIC(){
    if (pcap_findalldevs(&all_dev,err_buf) ==-1)
        ui->NICBox->addItem("Error: "+QString(err_buf));
    else {
        ui->NICBox->clear();
        ui->NICBox->addItem("Choose NIC");
        for (cur_dev = all_dev;cur_dev != NULL;cur_dev = cur_dev->next){
            QString dev_name = cur_dev->name;
            QString dev_desc = cur_dev->description;
            dev_name.replace("\\Device\\","");
            ui->NICBox->addItem(dev_name + " " + dev_desc);
        }
    }
}

void MainWindow::on_NICBox_currentIndexChanged(int index)
{
    if (!index) {
        cur_dev = 0;
        return;
    }
    int i;
    for (cur_dev = all_dev,i = 1; i!=index; cur_dev = cur_dev->next, i++);
    //set cur_dev to the dev you choose
}

int MainWindow::OpenCurDev(){
    if (!cur_dev) return -1;
    if (!(pcap_ptr = pcap_open_live(cur_dev->name,65536,1,1000,err_buf)) || // pcap_ptr!=NULL
        pcap_datalink(pcap_ptr) != DLT_EN10MB){ // only Ethernet
        pcap_freealldevs(all_dev);
        pcap_ptr = NULL;
        return -1;
    }
    statusBar()->showMessage(cur_dev->description); // bar below
    return 0;
}

void MainWindow::HandleMsg(DataPkt pkt){
    //qDebug()<<pkt.getTimestamp()<<" "<< pkt.getInfo();
    ui->PktTable->insertRow(pkt_count);
    this->pkt_vec.push_back(pkt);

    //choose color
    QString pkt_type = pkt.getPktType();
    QColor color;
    if (pkt_type == "TCP") color = QColor(216,191,216);
    else if (pkt_type == "UDP") color = QColor(144,238,144);
    else if (pkt_type == "ARP") color = QColor(238,138,0);
    else if (pkt_type == "ICMP") color = QColor(255,255,224);
    else color = QColor(255,218,185); //OTHER


    //insert a pkt into PktTable
    ui->PktTable->setItem(pkt_count,0,new QTableWidgetItem(QString::number(pkt_count)));//No.
    ui->PktTable->setItem(pkt_count,1,new QTableWidgetItem(pkt.getTimestamp()));    //time
    ui->PktTable->setItem(pkt_count,2,new QTableWidgetItem((pkt.getPktType() == "ARP" || pkt.getPktType() == "ETH_OTHER")?pkt.getEthInfo(INFO_ETH_ADDR_SRC):pkt.getIpInfo(INFO_ETH_ADDR_SRC)));//src
    ui->PktTable->setItem(pkt_count,3,new QTableWidgetItem((pkt.getPktType() == "ARP" || pkt.getPktType() == "ETH_OTHER")?pkt.getEthInfo(INFO_ETH_ADDR_DST):pkt.getIpInfo(INFO_ETH_ADDR_DST)));//dst
    ui->PktTable->setItem(pkt_count,4,new QTableWidgetItem(pkt.getPktType()));//protocol
    ui->PktTable->setItem(pkt_count,5,new QTableWidgetItem(QString::number(pkt.getDataLen())));//length
    ui->PktTable->setItem(pkt_count,6,new QTableWidgetItem(pkt.getInfo()));//info
    for (int i=0;i<7;i++){
        ui->PktTable->item(pkt_count,i)->setBackground(QBrush(color));
    }
    pkt_count++;
}

void MainWindow::on_PktTable_cellClicked(int row, int column) // prepare tree widget
{
    if (row==row_chosen) return;
    else {
        ui->PktTree->clear();
        ui->PktBrowser->clear();
        row_chosen = row;
//pkttree
    //eth
        QString eth_src = pkt_vec[row_chosen].getEthInfo(INFO_ETH_ADDR_SRC);
        QString eth_dst = pkt_vec[row_chosen].getEthInfo(INFO_ETH_ADDR_DST);
        QString eth_type = pkt_vec[row_chosen].getEthInfo(INFO_ETH_TYPE);
        QString eth_tree_str = "Ethernet, Src:" + eth_src + " Dst:" + eth_dst;
        QTreeWidgetItem *eth_tree_item = new QTreeWidgetItem(QStringList()<<eth_tree_str);
        ui->PktTree->addTopLevelItem(eth_tree_item);
        eth_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Destination: " + eth_dst));
        eth_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Source: " + eth_src));
        eth_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Type: " + eth_type));
    //ip
        if (pkt_vec[row_chosen].getPktType() == "TCP" ||
            pkt_vec[row_chosen].getPktType() == "UDP" ||
            pkt_vec[row_chosen].getPktType() == "ICMP" ||
            pkt_vec[row_chosen].getPktType() == "IP_OTHER"){
            //ip info
            QString ip_src = pkt_vec[row_chosen].getIpInfo(INFO_IP_ADDR_SRC);
            QString ip_dst = pkt_vec[row_chosen].getIpInfo(INFO_IP_ADDR_DST);
            QString ip_tree_str = "Internet Protocol Version 4, Src:" + ip_src + " Dst:" + ip_dst;
            QTreeWidgetItem *ip_tree_item = new QTreeWidgetItem(QStringList()<<ip_tree_str);
            ui->PktTree->addTopLevelItem(ip_tree_item);

            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Version: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_VERSION)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_HDR_LEN) + " bytes"));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Differentiated Services Field (TOS): " + pkt_vec[row_chosen].getIpInfo(INFO_IP_TOS)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Total Length: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_TOT_LEN)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Identfication: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_IDENT)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Flags: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_FLAGS)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_OFFSET)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Time to Live: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_TTL)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Protocol: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_PROTOCOL)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Header Checksum: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_CHECKSUM)));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Source: " + ip_src));
            ip_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Destination: " + ip_dst));

            //tcp
            if (pkt_vec[row_chosen].getPktType() == "TCP"){
                QString tcp_src_port = pkt_vec[row_chosen].getTcpInfo(INFO_TCP_SRC_PORT);
                QString tcp_dst_port = pkt_vec[row_chosen].getTcpInfo(INFO_TCP_DST_PORT);
                QString tcp_seq = pkt_vec[row_chosen].getTcpInfo(INFO_TCP_SEQ);
                QString tcp_ack = pkt_vec[row_chosen].getTcpInfo(INFO_TCP_ACK);
                QString tcp_pld_len = pkt_vec[row_chosen].getTcpInfo(INFO_TCP_PLD_LEN);    
                QString tcp_tree_str = "Transmission Control Protocol, Src Port:" + tcp_src_port + " Dst Port:" + tcp_dst_port
                                        + " Seq:" + tcp_seq + " Ack:" + tcp_ack + " Len:" + tcp_pld_len;
                QTreeWidgetItem *tcp_tree_item = new QTreeWidgetItem(QStringList()<<tcp_tree_str);
                ui->PktTree->addTopLevelItem(tcp_tree_item);
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + tcp_src_port));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + tcp_dst_port));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + tcp_seq));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + tcp_ack));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + pkt_vec[row_chosen].getTcpInfo(INFO_TCP_HDR_LEN) + " bytes"));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Flags: " + pkt_vec[row_chosen].getTcpInfo(INFO_TCP_FLAGS)));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + pkt_vec[row_chosen].getTcpInfo(INFO_TCP_WINDOW_SIZE)));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Checksum: " + pkt_vec[row_chosen].getTcpInfo(INFO_TCP_CHECKSUM)));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + pkt_vec[row_chosen].getTcpInfo(INFO_TCP_URG)));
                tcp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Payload Length: " + tcp_pld_len + " bytes"));
            }

            //udp
            else if (pkt_vec[row_chosen].getPktType() == "UDP"){
                QString udp_src_port = pkt_vec[row_chosen].getUdpInfo(INFO_UDP_SRC_PORT);
                QString udp_dst_port = pkt_vec[row_chosen].getUdpInfo(INFO_UDP_DST_PORT);
                QString udp_tree_str = "User Datagram Protocol, Src Port:" + udp_src_port + " Dst port:" + udp_dst_port;
                QTreeWidgetItem *udp_tree_item = new QTreeWidgetItem(QStringList()<<udp_tree_str);
                ui->PktTree->addTopLevelItem(udp_tree_item);
                udp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + udp_src_port));
                udp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + udp_dst_port));
                udp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Data Length: " + pkt_vec[row_chosen].getUdpInfo(INFO_UDP_DATA_LEN) + " bytes"));
                udp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Checksum: " + pkt_vec[row_chosen].getUdpInfo(INFO_UDP_CHECKSUM)));
                udp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Payload Length: " + pkt_vec[row_chosen].getUdpInfo(INFO_UDP_PLD_LEN) + " bytes"));
            }
            
            //icmp
            else if (pkt_vec[row_chosen].getPktType() == "ICMP"){
                QString icmp_tree_str = "Internet Control Message Protocol";
                QTreeWidgetItem *icmp_tree_item = new QTreeWidgetItem(QStringList()<<icmp_tree_str);
                ui->PktTree->addTopLevelItem(icmp_tree_item);
                icmp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Type: " + pkt_vec[row_chosen].getIcmpInfo(INFO_ICMP_TYPE)));
                icmp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Code: " + pkt_vec[row_chosen].getIcmpInfo(INFO_ICMP_CODE)));
                icmp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Checksum: " + pkt_vec[row_chosen].getIcmpInfo(INFO_ICMP_CHECKSUM)));
                icmp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + pkt_vec[row_chosen].getIcmpInfo(INFO_ICMP_IDENT)));
                icmp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + pkt_vec[row_chosen].getIcmpInfo(INFO_ICMP_SEQ)));
            }

            //other
            else {
                    QString other_tree_str = "Other, Protocol: " + pkt_vec[row_chosen].getIpInfo(INFO_IP_PROTOCOL);
                    QTreeWidgetItem *other_tree_item = new QTreeWidgetItem(QStringList()<<other_tree_str);
                    ui->PktTree->addTopLevelItem(other_tree_item);
            }

        }
    //arp
        else if (pkt_vec[row_chosen].getPktType() == "ARP"){
            QString arp_tree_str = "Address Resolution Protocol";
            QTreeWidgetItem *arp_tree_item = new QTreeWidgetItem(QStringList()<<arp_tree_str);
            ui->PktTree->addTopLevelItem(arp_tree_item);
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Hardware type: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_HW_TYPE)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Protocol type: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_PROTOCOL_TYPE)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Hardware size: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_ETH_LEN)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Protocol size: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_IP_LEN)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Opcode: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_OP_CODE)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Sender MAC address: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_MAC_SRC)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Sender IP address: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_MAC_DST)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Target MAC address: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_IP_SRC)));
            arp_tree_item->addChild(new QTreeWidgetItem(QStringList() << "Target IP address: " + pkt_vec[row_chosen].getArpInfo(INFO_ARP_IP_DST)));
        }
    //others
        else {
            QString other_tree_str = "Other";
            QTreeWidgetItem *other_tree_item = new QTreeWidgetItem(QStringList()<<other_tree_str);
            ui->PktTree->addTopLevelItem(other_tree_item);
        }
//pktbrowser
        QString pkt_content_display = "";
        int seg_limit = 2;
        int line_limit = 16;
        u_int pkt_len = pkt_vec[row_chosen].getDataLen();
        u_char *pkt_content_ptr = pkt_vec[row_chosen].getPktContent();
        for (u_int i = 0;i < pkt_len; i++){
            pkt_content_display += HextoS(pkt_content_ptr+i,1);
            if (i % line_limit == line_limit-1){
                pkt_content_display += "\n";
            }
            else if (i % seg_limit == seg_limit-1){
                pkt_content_display += " ";
            }
        }
        ui->PktBrowser->setText((const QString)pkt_content_display);
    }
}

void MainWindow::on_SrchFilter_returnPressed()
{
    QString text = ui->SrchFilter->text();
    text = text.toUpper();
    QString target = "#";
    if(text == "" || text == "UDP" || text == "TCP" || text == "ARP"|| text == "ICMP"){
        ui->SrchFilter->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
        target = text;
    }else{
        ui->SrchFilter->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
    int count = 0;
    int number = ui->PktTable->rowCount();
    if(!cap_status && target != "#"){
        if(target!=""){
            for(int i = 0;i < number;i++){
                if(ui->PktTable->item(i,4)->text() != target){
                    ui->PktTable->setRowHidden(i,true);
                }else{
                    ui->PktTable->setRowHidden(i,false);
                    count++;
                }
            }
        }else{
            int number = ui->PktTable->rowCount();
            for(int i = 0;i < number;i++){
                ui->PktTable->setRowHidden(i,false);
                count++;
            }
        }
    }

    double res = 0;
    if(number != 0)
        res = (count*100.0)/number;
    statusBar()->showMessage("Have show (" + QString::number(count) + ") " +QString::number(res,10,2) + "%");
}

/*
 * on_lineEdit_textChanged
 * when text at lineEdit changed,it will check input information is correct or not
 * if it is corrected,the color is green or it will be red
*/
void MainWindow::on_SrchFilter_textChanged(const QString &arg1)
{
    QString text = arg1;
    text = text.toLower();
    if(text == "" || text == "udp" || text == "tcp" || text == "arp" || text == "icmp"){
        ui->SrchFilter->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
    }else{
        ui->SrchFilter->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
}



QString MainWindow::HextoS(u_char *num,int size){ //hex-num to string
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
