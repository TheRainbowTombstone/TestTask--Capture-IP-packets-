#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QFileDialog>
#include "pcap_handle.h"
#include <QMessageBox>
#include <QInputDialog>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushFileBut_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, tr("Выберите файл"), QDir::homePath(), tr("Файлы PCAP (*.pcap *.cap)"));
    if (!filePath.isEmpty()) {
        QString savePath = QFileDialog::getSaveFileName(this, tr("Выберите место для сохранения CSV файла"), QDir::homePath(), tr("CSV файлы (*.csv)"));
        if (!savePath.isEmpty()) {
            QMessageBox::StandardButton reply = QMessageBox::question(this, "Задать количество пакетов?", "Хотите ли вы указать количество пакетов для захвата?", QMessageBox::Yes|QMessageBox::No);
            if (reply == QMessageBox::Yes) {
                bool ok;
                int packetCount = QInputDialog::getInt(this, tr("Укажите количество пакетов"), tr("Количество:"), 100, 0, 1000000, 1, &ok);
                if (ok) {

                    std::string pathStr = filePath.toStdString();
                    const char* convertFilePath = pathStr.c_str();

                    std::string savePathStr = savePath.toStdString();
                    const char* convertSavePath = savePathStr.c_str();

                    char errbuf[PCAP_ERRBUF_SIZE];
                    const char* filter_exp = "ip and (tcp or udp)";

                    PacketPcapProcessor pcap_proseccor;

                    if (strstr(filePath.toStdString().c_str(), ".pcap") != nullptr) {
                        FilePcapHandler source_pcap_handler;
                        pcap_proseccor.set_file_handler(&source_pcap_handler);


                        pcap_t* file_handle = source_pcap_handler.open_file(convertFilePath, errbuf);
                        if (file_handle != nullptr) {
                            pcap_proseccor.packet_capture(file_handle, filter_exp, packetCount);
                            source_pcap_handler.close_file(file_handle);
                        } else {
                            qDebug() << "Couldn't open source file: " << errbuf;
                            return;
                        }

                        qDebug() << "Выбранный файл:" << filePath;
                        qDebug() << "Выбранное место для сохранения CSV файла:" << savePath;
                        qDebug() << "Количество пакетов для захвата:" << packetCount;

                        CsvPcapHandler csvPcapHandler;
                        csvPcapHandler.write_to_csv(pcap_proseccor.get_threads(), convertSavePath);
                    }
                }
            }
        }
    }
}

void MainWindow::on_pushInterfaceBut_clicked()
{
    QString interfaceName = QInputDialog::getText(this, tr("Введите интерфейс"), tr("Интерфейс:"), QLineEdit::Normal, QDir::homePath());
    if (!interfaceName.isEmpty()) {
        QString savePath = QFileDialog::getSaveFileName(this, tr("Выберите место для сохранения CSV файла"), QDir::homePath(), tr("CSV файлы (*.csv)"));
        if (!savePath.isEmpty()) {
            QMessageBox::StandardButton reply = QMessageBox::question(this, "Задать количество пакетов?", "Хотите ли вы указать количество пакетов для захвата?", QMessageBox::Yes|QMessageBox::No);
            if (reply == QMessageBox::Yes) {
                bool ok;
                int packetCount = QInputDialog::getInt(this, tr("Укажите количество пакетов"), tr("Количество:"), 100, 0, 1000000, 1, &ok);
                if (ok) {


                    std::string pathStr = interfaceName.toStdString();
                    const char* convertInterfaceName = pathStr.c_str();

                    std::string savePathStr = savePath.toStdString();
                    const char* convertSavePath = pathStr.c_str();

                    char errbuf[PCAP_ERRBUF_SIZE];
                    const char* filter_exp = "ip and (tcp or udp)";

                    PacketPcapProcessor pcap_proseccor;

                    InterfacePcapHandler source_pcap_handler;
                    pcap_proseccor.set_interface_handler(&source_pcap_handler);

                    pcap_t* interface_handle = source_pcap_handler.open_interface(convertInterfaceName, errbuf);
                    if (interface_handle != nullptr) {
                    pcap_proseccor.packet_capture(interface_handle, filter_exp, packetCount);
                    source_pcap_handler.close_interface(interface_handle);
                    } else {
                    qDebug() << "Couldn't open live interface: " << errbuf;
                    return;
                    }

                    qDebug() << "Выбранный файл:" << interfaceName;
                    qDebug() << "Выбранное место для сохранения CSV файла:" << savePath;
                    qDebug() << "Количество пакетов для захвата:" << packetCount;

                    CsvPcapHandler csvPcapHandler;
                    csvPcapHandler.write_to_csv(pcap_proseccor.get_threads(), convertSavePath);
                }
            }
        }
    }
}
