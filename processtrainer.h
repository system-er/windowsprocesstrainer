#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_processtrainer.h"

class processtrainer : public QMainWindow
{
    Q_OBJECT

public:
    processtrainer(QWidget *parent = nullptr);
    ~processtrainer();

private:
    Ui::processtrainerClass ui;

    //Menu
    void on_MenuHelp_triggered();
    void on_MenuInfo_triggered();
    
    //Button
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();

    //tableWidget
    void on_tableWidget_cellChanged(int, int);
};
