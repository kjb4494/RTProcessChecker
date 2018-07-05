import ProcessInfo
import pprint
import sys
import test_qt
from PyQt5.QtWidgets import QApplication


def ProcessCheckerView(info):
    app = QApplication(sys.argv)
    form = test_qt.Form()
    form.init_widget(info)
    form.show()
    exit(app.exec_())

def main():

    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning()

    #pprint.pprint(obPInfo.dic_processList)
    ProcessCheckerView(obPInfo.dic_processList)

if __name__ == "__main__":
    main()
