#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "capThread.h"
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ListNIC(); // display NIC in NICBox
    capThread *cap_thread = new capThread;
    static bool index = false;
    connect(ui->actionrunstop,&QAction::triggered,this,[=]{
        index = !index; // on - off
        if (index) { // on
            if (PktCapture() != -1){
                cap_thread->setFlag();
                cap_thread->setPcapPtr(pcap_ptr);
                cap_thread->start();
                ui->actionrunstop->setText("stop");
                ui->NICBox->setEnabled(false);
            }
        }
        else {
            cap_thread->resetFlag();
            cap_thread->quit();
            cap_thread->wait(); //wait to release resources
            ui->actionrunstop->setText("run");
            ui->NICBox->setEnabled(true);
            pcap_close(pcap_ptr);
            pcap_ptr = NULL;
        }
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::ListNIC(void){
    int n = pcap_findalldevs(&all_dev,err_buf);
    if (n==-1) ui->NICBox->addItem("Error: "+QString(err_buf));
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
    if (!index) return;
    int i;
    for (cur_dev = all_dev,i = 1;i!=index;cur_dev = cur_dev->next, i++);
}

int MainWindow::PktCapture(void){
    if (!cur_dev) return -1;
    if (!(pcap_ptr = pcap_open_live(cur_dev->name,65536,1,1000,err_buf)) || // pcap_ptr!=NULL
        pcap_datalink(pcap_ptr) != DLT_EN10MB){ // only Ethernet
        pcap_freealldevs(all_dev);
        return -1;
    }
    statusBar()->showMessage(cur_dev->description); // bar below
    return 0;
}

