#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
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
    ~MainWindow();
    void ListNIC();
    int OpenCurDev();

public slots:
    void HandleMsg(DataPkt pkt);

private slots:
    void on_NICBox_currentIndexChanged(int index);

    void on_PktTable_cellClicked(int row, int column);

private:
    Ui::MainWindow *ui;
    QVector<DataPkt> pkt_vec;
    int pkt_count;

    pcap_if_t *all_dev;
    pcap_if_t *cur_dev;
    pcap_t *pcap_ptr;
    char err_buf[PCAP_ERRBUF_SIZE];

    int row_chosen;

protected:
    QString HextoS(u_char *num,int size);
};
#endif // MAINWINDOW_H
