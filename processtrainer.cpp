#include "processtrainer.h"
#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
//#include <WtsApi32.h>
#include <QMessageBox>
#include <QList>


//globals
bool bytesizechecked[3];


struct structprocess {             // Structure declaration
    int pid;         // Member (int variable)
    QString processname;   // Member (string variable)
    QString fullname;
};       // Structure variable 
QList<structprocess> runningprocesses;

struct AddressInfo
{
    uintptr_t address;
    int byteSize;
};

std::vector<uintptr_t> foundaddresses;
std::vector<uintptr_t> filteredaddresses;
std::vector<AddressInfo> foundaddressinfos;
std::vector<AddressInfo> filteredaddressinfos;

void ErrorBox(QString es)
{
    QMessageBox msgBox;

    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setWindowTitle("Warning");
    msgBox.setText(es);
    msgBox.exec();
}

void InfoBox(QString info)
{
    QMessageBox msgBox;

    msgBox.setIcon(QMessageBox::Information);
    msgBox.setWindowTitle("Information");
    msgBox.setText(info);
    msgBox.exec();
}



std::vector<uintptr_t> SearchNumber(DWORD processId, int number)
{
    std::vector<uintptr_t> addresses;

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle)
    {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        MEMORY_BASIC_INFORMATION memoryInfo;
        uintptr_t address = 0;
        while ((LPVOID)address < systemInfo.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
            {
                if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Type == MEM_PRIVATE || memoryInfo.Type == MEM_MAPPED))
                {
                    BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead))
                    {
                        for (size_t i = 0; i < bytesRead - sizeof(int); ++i)
                        {
                            if (*reinterpret_cast<int*>(buffer + i) == number)
                            {
                                addresses.push_back(reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i);
                            }
                        }
                    }
                    delete[] buffer;
                }
            }
            address += memoryInfo.RegionSize;
        }
        CloseHandle(processHandle);
    }

    return addresses;
}


std::vector<uintptr_t> SearchNumberBytesize(DWORD processId, int number, int byteSize)
{
    std::vector<uintptr_t> addresses;

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle)
    {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        MEMORY_BASIC_INFORMATION memoryInfo;
        uintptr_t address = 0;
        while ((LPVOID)address < systemInfo.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
            {
                if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Type == MEM_PRIVATE || memoryInfo.Type == MEM_MAPPED))
                {
                    BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead))
                    {
                        for (size_t i = 0; i < bytesRead - byteSize; ++i)
                        {
                            int value = 0;
                            if (byteSize == 1)
                            {
                                value = buffer[i];
                            }
                            else if (byteSize == 2)
                            {
                                value = *reinterpret_cast<short*>(buffer + i);
                            }
                            else if (byteSize == 4)
                            {
                                value = *reinterpret_cast<int*>(buffer + i);
                            }

                            if (value == number)
                            {
                                addresses.push_back(reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i);
                            }
                        }
                    }
                    delete[] buffer;
                }
            }
            address += memoryInfo.RegionSize;
        }
        CloseHandle(processHandle);
    }

    return addresses;
}



std::vector<AddressInfo> SearchNumberSizes(DWORD processId, int number)
{
    std::vector<AddressInfo> addresses;

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle)
    {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        MEMORY_BASIC_INFORMATION memoryInfo;
        uintptr_t address = 0;
        while ((LPVOID)address < systemInfo.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
            {
                if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Type == MEM_PRIVATE || memoryInfo.Type == MEM_MAPPED))
                {
                    BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead))
                    {
                        if (bytesizechecked[0])
                        {
                            for (size_t i = 0; i < bytesRead - 4; ++i)
                            {
                                if (*reinterpret_cast<int*>(buffer + i) == number)
                                {
                                    AddressInfo info;
                                    info.address = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                    info.byteSize = 4;
                                    bool addressdouble = false;
                                    for (int j = 0; j < addresses.size(); j++)
                                    {
                                        if (addresses[j].address == info.address) addressdouble = true;
                                    }
                                    if (!addressdouble) addresses.push_back(info);
                                }
                            }
                        }

                        if (bytesizechecked[1])
                        {
                            for (size_t i = 0; i < bytesRead - 2; ++i)
                            {
                                if (*reinterpret_cast<short*>(buffer + i) == number)
                                {
                                    AddressInfo info;
                                    info.address = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                    info.byteSize = 2;
                                    bool addressdouble = false;
                                    for (int j = 0; j < addresses.size(); j++)
                                    {
                                        if (addresses[j].address == info.address) addressdouble = true;
                                    }
                                    if (!addressdouble) addresses.push_back(info);
                                }
                            }
                        }

                        if (bytesizechecked[2])
                        {
                            for (size_t i = 0; i < bytesRead - 1; ++i)
                            {
                                if (buffer[i] == number)
                                {
                                    AddressInfo info;
                                    info.address = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                    info.byteSize = 1;
                                    bool addressdouble = false;
                                    for (int j = 0; j < addresses.size(); j++)
                                    {
                                        if (addresses[j].address == info.address) addressdouble = true;
                                    }
                                    if (!addressdouble) addresses.push_back(info);
                                }
                            }
                        }
                    }
                    delete[] buffer;
                }
            }
            address += memoryInfo.RegionSize;
        }
        CloseHandle(processHandle);
    }

    return addresses;
}



void FilterNumberSizesList(DWORD processId, int number)
{
    filteredaddressinfos.clear();
    filteredaddressinfos.resize(0);
    filteredaddressinfos.shrink_to_fit();

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle)
    {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        //MEMORY_BASIC_INFORMATION memoryInfo;
        //if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Type == MEM_PRIVATE || memoryInfo.Type == MEM_MAPPED))
        //{
            for (int i = 0; i < foundaddressinfos.size(); i++)
            {
                BYTE* buffer = new BYTE[foundaddressinfos[i].byteSize];
                SIZE_T bytesRead;
                if (ReadProcessMemory(processHandle, (LPVOID)foundaddressinfos[i].address, buffer, foundaddressinfos[i].byteSize, &bytesRead))
                {
                    //OutputDebugStringW(L"My output string.");
                    if (*reinterpret_cast<int*>(buffer) == number)
                    {
                        AddressInfo info;
                        info.address = foundaddressinfos[i].address;
                        info.byteSize = foundaddressinfos[i].byteSize;
                        filteredaddressinfos.push_back(info);
                    }
                }
                delete[] buffer;
            }
        //}
    }

    foundaddressinfos.clear();
    foundaddressinfos.resize(0);
    foundaddressinfos.shrink_to_fit();

    for (int i = 0; i < filteredaddressinfos.size(); i++)
    {
        AddressInfo info;
        info.address = filteredaddressinfos[i].address;
        info.byteSize = filteredaddressinfos[i].byteSize;
        //foundaddressinfos.push_back(info);
        bool addressdouble = false;
        for (int j = 0; j < foundaddressinfos.size(); j++)
        {
            if (filteredaddressinfos[j].address == info.address) addressdouble = true;
        }
        if (!addressdouble) foundaddressinfos.push_back(info);
    }
}


void FilterNumberSizes(DWORD processId, int number)
{
    filteredaddressinfos.clear();
    filteredaddressinfos.resize(0);
    filteredaddressinfos.shrink_to_fit();

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle)
    {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        MEMORY_BASIC_INFORMATION memoryInfo;
        uintptr_t address = 0;
        while ((LPVOID)address < systemInfo.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
            {
                if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Type == MEM_PRIVATE || memoryInfo.Type == MEM_MAPPED))
                {
                    BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead))
                    {

                        for (size_t i = 0; i < bytesRead - 4; ++i)
                        {
                            if (*reinterpret_cast<int*>(buffer + i) == number)
                            {
                                AddressInfo info;
                                info.address = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                info.byteSize = 4;
                                //addresses.push_back(info);
                                for (int j = 0; j < foundaddressinfos.size(); j++)
                                {
                                    if (info.address == foundaddressinfos[j].address)
                                    {
                                        filteredaddressinfos.push_back(info);
                                    }
                                }
                            }
                        }

                        for (size_t i = 0; i < bytesRead - 2; ++i)
                        {
                            if (*reinterpret_cast<short*>(buffer + i) == number)
                            {
                                AddressInfo info;
                                info.address = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                info.byteSize = 2;
                                //addresses.push_back(info);
                                for (int j = 0; j < foundaddressinfos.size(); j++)
                                {
                                    if (info.address == foundaddressinfos[j].address)
                                    {
                                        filteredaddressinfos.push_back(info);
                                    }
                                }
                            }
                        }

                        for (size_t i = 0; i < bytesRead - 1; ++i)
                        {
                            if (buffer[i] == number)
                            {
                                AddressInfo info;
                                info.address = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                                info.byteSize = 1;
                                //addresses.push_back(info);
                                for (int j = 0; j < foundaddressinfos.size(); j++)
                                {
                                    if (info.address == foundaddressinfos[j].address)
                                    {
                                        filteredaddressinfos.push_back(info);
                                    }
                                }
                            }
                        }
                    }
                    delete[] buffer;
                }
            }
            address += memoryInfo.RegionSize;
        }
        CloseHandle(processHandle);
    }

    //return addresses;
    foundaddressinfos.clear();
    foundaddressinfos.resize(0);
    foundaddressinfos.shrink_to_fit();

    for (int i = 0; i < filteredaddressinfos.size(); i++)
    {
        AddressInfo info;
        info.address = filteredaddressinfos[i].address;
        info.byteSize = filteredaddressinfos[i].byteSize;
        //foundaddressinfos.push_back(info);
        bool addressdouble = false;
        for (int j = 0; j < foundaddressinfos.size(); j++)
        {
            if (filteredaddressinfos[j].address == info.address) addressdouble = true;
        }
        if (!addressdouble) foundaddressinfos.push_back(info);
    }
}




void FilterNumber(DWORD processId, int number)
{
    filteredaddresses.clear();
    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle)
    {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        MEMORY_BASIC_INFORMATION memoryInfo;
        uintptr_t address = 0;

        while ((LPVOID)address < systemInfo.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
            {
                if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Type == MEM_PRIVATE || memoryInfo.Type == MEM_MAPPED))
                {
                    BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead))
                    {
                        for (size_t i = 0; i < bytesRead - sizeof(int); ++i)
                        {
                            if (*reinterpret_cast<int*>(buffer + i) == number)
                            {
                                //addresses.push_back(reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i);
                                for (int j = 0; j < foundaddresses.size(); j++)
                                {
                                    if ((reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i) == foundaddresses[j])
                                    {
                                        filteredaddresses.push_back(reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i);
                                    }
                                }
                            }
                        }
                    }
                    delete[] buffer;
                }
            }
            address += memoryInfo.RegionSize;
        }
        CloseHandle(processHandle);
    }

    foundaddresses.clear();
    for (int i = 0; i < filteredaddresses.size(); i++)
    {
        foundaddresses.push_back(filteredaddresses[i]);
    }
}


bool EditMemoryAddress(DWORD processId, uintptr_t address, int newValue)
{
    HANDLE processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, processId);
    if (processHandle)
    {
        int value;
        if (ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), nullptr))
        {
            if (WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(address), &newValue, sizeof(newValue), nullptr))
            {
                CloseHandle(processHandle);
                return true;
            }
        }
        CloseHandle(processHandle);
    }
    return false;
}




processtrainer::processtrainer(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    //Menu
    connect(ui.actionHelp, &QAction::triggered, this, &processtrainer::on_MenuHelp_triggered);
    connect(ui.actionInfo, &QAction::triggered, this, &processtrainer::on_MenuInfo_triggered);

    //Button
    connect(ui.pushButton, &QPushButton::clicked, this, &processtrainer::on_pushButton_clicked);
    connect(ui.pushButton_2, &QPushButton::clicked, this, &processtrainer::on_pushButton_2_clicked);

    //tableWidget
    connect(ui.tableWidget, &QTableWidget::cellChanged, this, &processtrainer::on_tableWidget_cellChanged);

    //ui.comboBox->addItem("one");
    //ui.comboBox->addItem("two");
    //ui.comboBox->addItem("three");
    

    //QList<structprocess> runningprocesses;
    QString s;
    HANDLE hndl = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (hndl)
    {
        PROCESSENTRY32  process = { sizeof(PROCESSENTRY32) };
        Process32First(hndl, &process);
        do
        {
            structprocess r;
            r.pid = process.th32ProcessID;
            //process.
            r.processname = QString::fromWCharArray(process.szExeFile);
            runningprocesses.push_back(r);
            s = QString::number(process.th32ProcessID)+" "+ QString::fromWCharArray(process.szExeFile);
            ui.comboBox->addItem(s);
        } while (Process32Next(hndl, &process));

        CloseHandle(hndl);
    }

    ui.comboBox->setCurrentIndex(runningprocesses.size() - 1);
    QStringList headers;
    headers << "address" << "bytes" << "value";
    ui.tableWidget->setHorizontalHeaderLabels(headers);
    ui.tableWidget->blockSignals(true);

}


processtrainer::~processtrainer()
{}



void processtrainer::on_MenuHelp_triggered()
{
    QMessageBox msgBox;
    QString Info;

    Info = "windowsprocesstrainer\nfirst: select the process\noptional: uncheck bytesize for faster speed\nsecond: type a search value\nthen press search button\nthird: if too much addresses found filter\nfourth: change value\n";
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setWindowTitle("Information");
    msgBox.setText(Info);
    msgBox.exec();
}

void processtrainer::on_MenuInfo_triggered()
{
    QMessageBox msgBox;
    QString Info;

    Info = "windowsprocesstrainer\nVersion 0.3\nCopyright 2023\nsystemerror\nemail: sys_temerror at web dot de\n";
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setWindowTitle("Information");
    msgBox.setText(Info);
    msgBox.exec();
}



void processtrainer::on_pushButton_clicked()
{
    ui.tableWidget->blockSignals(true);
    QStringList headers;
    headers << "address" << "bytes" << "value";
    
    bytesizechecked[0] = ui.checkBox->checkState();
    bytesizechecked[1] = ui.checkBox_2->checkState();
    bytesizechecked[2] = ui.checkBox_3->checkState();

    foundaddressinfos.clear();
    foundaddressinfos.resize(0);
    foundaddressinfos.shrink_to_fit();
    //processtrainer::ui.label_2->setText("selected process: " + runningprocesses[ui.comboBox->currentIndex()].processname);

    //const char someData[] = "a";
    //std::cout << "Local data address: " << (void*)someData << "\n";

    //Pass whatever process id you like here instead.
    //DWORD pid = GetCurrentProcessId();
    //std::vector<uintptr_t> foundaddresses;
    QString searchvalue = ui.lineEdit->text();
    if (searchvalue == "")
    {
        ErrorBox("Searchvalue empty!\nPlease type a value.");
    }
    else
    {
        //foundaddresses = SearchNumber(runningprocesses[ui.comboBox->currentIndex()].pid, searchvalue.toInt());
        foundaddressinfos = SearchNumberSizes(runningprocesses[ui.comboBox->currentIndex()].pid, searchvalue.toInt());
        int rc = 0;
        int n = 0;
        if (sizeof(foundaddressinfos) > 0)
        {
            //QString myString = QString::fromUtf8(ret);
            ui.label_4->setText("addresses found: " + QString::number(foundaddressinfos.size()));
            ui.tableWidget->clear();
            ui.tableWidget->clearContents();
            ui.tableWidget->reset();
            ui.tableWidget->setRowCount(0);
            ui.tableWidget->setHorizontalHeaderLabels(headers);
            ui.tableWidget->update();
            for (int i = 0; i < foundaddressinfos.size(); i++)
            {
                rc = ui.tableWidget->rowCount();
                ui.tableWidget->insertRow(rc);
                //ui.tableWidget->setItem(rc, 0, new QTableWidgetItem(QString::number(i)));
                ui.tableWidget->setItem(rc, 0, new QTableWidgetItem(QString::number(foundaddressinfos[i].address, 16).toUpper()));
                ui.tableWidget->setItem(rc, 1, new QTableWidgetItem(QString::number(foundaddressinfos[i].byteSize, 16).toUpper()));
                ui.tableWidget->setItem(rc, 2, new QTableWidgetItem(QString::number(searchvalue.toInt())));
                //ui.tableWidget->setItem(rc, 2, new QTableWidgetItem(QString::number(42)));
                //ui->listWidget->repaint();
            }
        }
    }
    ui.tableWidget->blockSignals(false);
}


void processtrainer::on_pushButton_2_clicked()
{
    ui.tableWidget->blockSignals(true);
    QStringList headers;
    headers << "address" << "bytes" << "value";
    //processtrainer::ui.label_2->setText("selected process: " + runningprocesses[ui.comboBox->currentIndex()].processname);

    //const char someData[] = "a";
    //std::cout << "Local data address: " << (void*)someData << "\n";

    //Pass whatever process id you like here instead.
    //DWORD pid = GetCurrentProcessId();
    //std::vector<uintptr_t> foundaddresses;
    QString filtervalue = ui.lineEdit_2->text();
    if (filtervalue == "")
    {
        ErrorBox("Filtervalue empty!\nPlease type a value.");
    }
    else
    {
        //FilterNumberSizes(runningprocesses[ui.comboBox->currentIndex()].pid, filtervalue.toInt());
        FilterNumberSizesList(runningprocesses[ui.comboBox->currentIndex()].pid, filtervalue.toInt());
        ui.tableWidget->clear();
        ui.tableWidget->clearContents();
        ui.tableWidget->reset();
        ui.tableWidget->setRowCount(0);
        ui.tableWidget->setHorizontalHeaderLabels(headers);
        ui.tableWidget->update();
        ui.label_4->setText("addresses found: ");
        int rc = 0;
        if (foundaddressinfos.size() > 0)
        {
            //QString myString = QString::fromUtf8(ret);
            ui.label_4->setText("addresses found: " + QString::number(foundaddressinfos.size()));
            for (int i = 0; i < foundaddressinfos.size(); i++)
            {
                rc = ui.tableWidget->rowCount();
                ui.tableWidget->insertRow(rc);
                //ui.tableWidget->setItem(rc, 0, new QTableWidgetItem(QString::number(i)));
                ui.tableWidget->setItem(rc, 0, new QTableWidgetItem(QString::number(foundaddressinfos[i].address, 16).toUpper()));
                ui.tableWidget->setItem(rc, 1, new QTableWidgetItem(QString::number(foundaddressinfos[i].byteSize, 16).toUpper()));
                ui.tableWidget->setItem(rc, 2, new QTableWidgetItem(QString::number(filtervalue.toInt())));
            }
        }
    }
    ui.tableWidget->blockSignals(false);
}


void processtrainer::on_tableWidget_cellChanged(int row, int col)
{
    //InfoBox("row:"+QString::number(row)+"  col:" + QString::number(col) + " new: " + ui.tableWidget->item(row, col)->text());
    EditMemoryAddress(runningprocesses[ui.comboBox->currentIndex()].pid, 
        foundaddressinfos[row].address, 
        ui.tableWidget->item(row, col)->text().toInt());
}


