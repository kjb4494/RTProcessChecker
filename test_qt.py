#!/usr/bin/env python
# coding: utf-8

# 예제 내용
# * QTreeWidget을 사용하여 아이템을 표시

from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QTreeWidget
from PyQt5.QtCore import QVariant
from PyQt5.QtWidgets import QTreeWidgetItem
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QThread
from PyQt5.QtCore import pyqtSignal
import time

global count
count = 0

class TicGenerator(QThread):
    """
    5초마다 틱 신호를 전달
    """
    # 사용자 정의 시그널 선언
    # 외부에서 사용할때 tic대신 Tic을 이용하여 호출할 수 있다.
    # Qt의 시그널 및 슬롯 이름은 Camel을 사용하기 때문에 파이썬의 PEP8을 지키면서 작성한다면 name을 반드시 사용
    tic = pyqtSignal(name="Tic")

    def __init__(self):
        QThread.__init__(self)

    def __del__(self):
        self.wait()

    def run(self):
        while True:
            t = int(time.time())
            if not t % 5 == 0:
                self.usleep(1)
                continue
            self.Tic.emit()
            self.msleep(1000)

class Form(QWidget):
    def __init__(self):
        QWidget.__init__(self, flags=Qt.Widget)
        self.setWindowTitle("Progress Checker")
        self.setFixedWidth(1000)
        self.setFixedHeight(600)
        self.tw = QTreeWidget(self)
        self.tic_gen = TicGenerator()



    def init_widget(self, info):
        # 데이터
#        obPrInfo = ProcessInfo.ProcessInfo()
#        obPrInfo.firstScanning()
#        dicPsList = obPrInfo.dic_processList
#       for processId in dicPsList:
#            if len(dicPsList[processId]['port'])>1:
#                print(dicPsList[processId]['port'][0])


        # QTreeView 생성 및 설정

        self.tw.setFixedWidth(1000)
        self.tw.setFixedHeight(600)
        self.tw.setColumnCount(8)
        self.tw.setHeaderLabels(["Process Name", "PID", "Inject", "VT", "WOT", "Remote Port", "Remote IP", "DNS"])
        self.tw.setSortingEnabled(1)
        #self.update_view(info)

        self.tic_gen.Tic.connect(lambda : self.update_view(info))
        self.tic_gen.start()

    def add_tree_root(self, Process_Name:str, PID:int, Inject:str, VT: str, WOT:str, Remote_Port:str, Remote_IP:str, DNS:str):
        item = QTreeWidgetItem(self.tw)
        item.setText(0, Process_Name)
        item.setText(1, str(PID))
        item.setText(2, Inject)
        item.setText(3, VT)
        item.setText(4, WOT)
        item.setText(5, str(Remote_Port))
        item.setText(6, str(Remote_IP))
        item.setText(7, str(DNS))
        return item

    def add_tree_child(self, parent:QTreeWidgetItem, name:str, description:str):
  #      item = QTreeWidgetItem()
  #      item.setText(0, name)
  #      item.setText(1, description)
  #     parent.addChild(item)
  #      return item
        return

    def update_view(self, data:dict):
        self.tw.clear()
        global count
        count= count+1
        self.setWindowTitle("Progress Checker:{}".format(count))
        for processId in data:
            num = len(data[processId]['port'])
            #print(data[processId]['port'])
            if num > 1:
                for i in range(0, num):
                    self.add_tree_root(data[processId]['name'],
                                       processId,
                                       data[processId]['inject'],
                                       data[processId]['vt'],
                                       data[processId]['wot'],
                                       data[processId]['port'][i],
                                       data[processId]['rAddIp'][i],
                                       data[processId]['dns'][i])
            else :
                self.add_tree_root(data[processId]['name'],
                                   processId,
                                   data[processId]['inject'],
                                   data[processId]['vt'],
                                   data[processId]['wot'],
                                   data[processId]['port'],
                                   data[processId]['rAddIp'],
                                   data[processId]['dns'])



#if __name__ == "__main__":
#    import sys
#    app = QApplication(sys.argv)
#    form = Form()
#    form.show()
#    exit(app.exec_())