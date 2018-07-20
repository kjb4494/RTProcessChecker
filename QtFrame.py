
from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QTreeWidget
from PyQt5.QtCore import QVariant
from PyQt5.QtWidgets import QTreeWidgetItem
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QThread
from PyQt5.QtCore import pyqtSignal
import time
import RealTimeUpdateManager as rtum
import threading
from PyQt5.QtGui import *

class TicGenerator(QThread):
    """
    5초마다 틱 신호를 전달
    """
    # 사용자 정의 시그널 선언
    # 외부에서 사용할때 tic대신 Tic을 이용하여 호출할 수 있다.
    # Qt의 시그널 및 슬롯 이름은 Camel을 사용하기 때문에 파이썬의 PEP8을
    # 지키면서 작성한다면 name을 반드시 사용
    tic = pyqtSignal(name="Tic")

    def __init__(self):
        QThread.__init__(self)

    def __del__(self):
        self.wait()

    def run(self):
        while True:
            t = int(time.time())
            if not t % 2 == 0:
                self.usleep(1)
                continue
            self.Tic.emit()
            self.msleep(500)

class Form(QWidget):


    def __init__(self):

        QWidget.__init__(self, flags=Qt.Widget)
        self.setWindowTitle("Progress Checker")
        self.setFixedWidth(1000)
        self.setFixedHeight(600)
        self.tw = QTreeWidget(self)
        self.tw.setAlternatingRowColors(True)
        self.tic_gen = TicGenerator()
        self.count = 0
        self.cloneDic = {}
        self.clickedData = []

        #icon
        style = QApplication.style()
        self.file_all = style.standardIcon(QStyle.SP_FileIcon)


        # Item 임시 저장 변수
        self.pName = ""
        self.pid = ""
        self.inject = ""
        self.vt = ""
        self.wot = ""
        self.remotePort = ""
        self.remoteIp = ""
        self.dns = ""
        self.path = ""
        self.vtInfo = {}
        self.injectInfo = []

        # 스레드 핸들링을 위한 플래그 변수
        self.vtFlag = False
        self.psFlag = False
        self.gsbFlag = False
        
        # Tooltip 을 출력하기 위한 플래그 변수
        self.ttFlag = False
        self.ttData = ""

        # SetSelected 를 출력하기 위한 플래그 변수
        self.ssFlag = False

    def init_widget(self, ProcessInfo, OperInject):
        # QTreeView 생성 및 설정
        self.ProcessInfo = ProcessInfo
        self.OperInject = OperInject
        self.tw.setFixedWidth(1000)
        self.tw.setFixedHeight(600)
        self.tw.setColumnCount(9)
        self.tw.setHeaderLabels(["*", "Process Name", "PID", "Inject", "VT", "GSB", "Remote Port", "Remote IP", "DNS"])
        self.tw.setSortingEnabled(True)
        self.tw.itemClicked.connect(self.get_item_info)
        self.tic_gen.Tic.connect(lambda: self.update_view())
        self.tic_gen.start()

    def add_tree_root(self):

        item = QTreeWidgetItem(self.tw)

        item.setIcon(0, self.file_all)
        item.setText(1, self.pName)
        item.setText(2, self.pid)
        item.setText(3, self.inject)
        item.setText(4, self.vt)
        item.setText(5, self.wot)
        item.setText(6, self.remotePort)
        item.setText(7, self.remoteIp)
        item.setText(8, self.dns)

        item.setData(11, 1, self.vtInfo)
        item.setData(11, 2, self.injectInfo)
        item.setData(11, 3, self.pid)
        item.setData(11, 4, self.remotePort)
        item.setData(11, 5, self.remoteIp)
        item.setData(11, 6, self.path)
        if self.ssFlag == True:
            item.setSelected(True)
            self.ssFlag = False

    def get_item_info(self, item):
        try:
            #print("=== Injected Info ===")
            #print("\n".join(item.data(11, 2)))
            #print("=== VirusTotal Report ===")
            #print("\n".join("{}: {}".format(vtInfo, item.data(11, 1)[vtInfo]) for vtInfo in item.data(11, 1)))
            #print(item.data(11, 1))
            #self.tw.setToolTip("=== VirusTotal Report ===" + "\n".join("{}: {}".format(vtInfo, item.data(11, 1)[vtInfo]) for vtInfo in item.data(11, 1)))
            self.ttFlag = True
            self.ttData = "=== VirusTotal Report ===\n" + "\n".join("{}: {}".format(vtInfo, item.data(11, 1)[vtInfo]) for vtInfo in item.data(11, 1))
            self.clickedData = [item.data(11, 3), item.data(11, 4), item.data(11, 5), item.data(11, 6)]

            #self.clkFlag = True

        except:
            return

    def update_view(self):
        # 화면 갱신
        self.tw.clear()
        
        if self.ttFlag:
            self.tw.setToolTip(self.ttData)
            self.ttFlag = False
        # self.count = self.count + 1
        # self.setWindowTitle("Progress Checker:{}".format(self.count))
        # vt를 실시간으로 갱신하는 스레드
        if not self.vtFlag:
            self.vtFlag = True
            vtThread = threading.Thread(target=rtum.importVt, args=(self, ))
            vtThread.daemon = True
            vtThread.start()

        # malware 실시간으로 검사하여 딕셔너리를 갱시하는 스레드
        if not self.gsbFlag:
            self.gsbFlag = True
            gsbThread = threading.Thread(target=rtum.updateGsb, args=(self,))
            gsbThread.daemon = True
            gsbThread.start()

        # 리소스 동시참조를 막기 위한 리스트 복사
        if not self.psFlag:
            self.cloneDic = self.ProcessInfo.dic_processList.copy()

        # 프로세스 정보 갱신
        if not self.psFlag:
            self.psFlag = True
            psThread = threading.Thread(target=rtum.updateRTProcess, args=(self,))
            psThread.daemon = True
            psThread.start()

        pcList = self.cloneDic
        for pid in pcList:
            data = pcList[pid]

            self.pid = str(pid)
            self.pName = data['name']
            self.inject = data['inject']
            self.injectInfo = data['injectInfo']
            self.vt = data['vt']
            self.vtInfo = data['vtInfo']
            self.path = data['path']
            remoteData = data['remote']

            if len(remoteData):
                for i in range(len(remoteData)):
                    self.wot = remoteData[i]['gsb']
                    self.remotePort = str(remoteData[i]['port'])
                    self.remoteIp = remoteData[i]['ip']
                    self.dns = remoteData[i]['dns']

                    # 이전에 클릭한 데이터가 있을 경우 유지
                    if self.clickedData:
                        if self.pid == self.clickedData[0] and \
                                self.remotePort == self.clickedData[1] and \
                                self.remoteIp == self.clickedData[2] and \
                                self.path == self.clickedData[3]:
                            self.ssFlag = True

                    self.add_tree_root()
            else:
                self.wot = ""
                self.remotePort = ""
                self.remoteIp = ""
                self.dns = ""
                self.add_tree_root()




