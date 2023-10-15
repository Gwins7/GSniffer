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
    ui->PktTable->setColumnWidth(6,500);

    ui->PktTable->setShowGrid(false); // disable column separate line display
    ui->PktTable->verticalHeader()->setVisible(false); // disable table No.
    ui->PktTable->setSelectionBehavior(QAbstractItemView::SelectRows); // select the whole row
    ui->PktTable->setItemDelegate(new ReadOnlyDelegate); //can't edit the pkttable

    // function init
    cur_dev = 0;
    capThread *cap_thread = new capThread;
    static bool cap_status = false;

    connect(ui->actionrunstop,&QAction::triggered,this,[=]{ // set action on run/stop
        cap_status = !cap_status; // on - off
        if (cap_status) { // on

            //clear previous content
            ui->PktTable->clearContents();
            ui->PktTable->setRowCount(0);
            pkt_count = 0;
            row_chosen = -1;
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
    else if (pkt_type == "DNS") color = QColor(255,255,224);
    else color = QColor(255,218,185);

    //insert a pkt into PktTable
    ui->PktTable->setItem(pkt_count,0,new QTableWidgetItem(QString::number(pkt_count)));//No.
    ui->PktTable->setItem(pkt_count,1,new QTableWidgetItem(pkt.getTimestamp()));    //time
    ui->PktTable->setItem(pkt_count,2,new QTableWidgetItem(pkt.getPktType() == "ARP"?pkt.getEthSrc():pkt.getIpSrc()));//src
    ui->PktTable->setItem(pkt_count,3,new QTableWidgetItem(pkt.getPktType() == "ARP"?pkt.getEthDst():pkt.getIpDst()));//dst
    ui->PktTable->setItem(pkt_count,4,new QTableWidgetItem(pkt.getPktType()));//protocol
    ui->PktTable->setItem(pkt_count,5,new QTableWidgetItem(pkt.getDataLen()));//length
    ui->PktTable->setItem(pkt_count,6,new QTableWidgetItem(pkt.getInfo()));//info
    for (int i=0;i<7;i++){
        ui->PktTable->item(pkt_count,i)->setBackground(QBrush(color));
    }
    pkt_count++;
}

void MainWindow::on_PktTable_cellClicked(int row, int column) // prepare tree widget
{

}

