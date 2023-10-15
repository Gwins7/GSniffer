#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "winsock2.h"
#include "pcap.h"
#include "datapkt.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow(void);
    void ListNIC(void);
    int OpenCurDev(void);

public slots:
    void HandleMsg(DataPkt pkt);

private slots:
    void on_NICBox_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_dev;
    pcap_if_t *cur_dev;
    pcap_t *pcap_ptr;
    char err_buf[PCAP_ERRBUF_SIZE];

};
#endif // MAINWINDOW_H
