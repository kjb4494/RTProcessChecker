import ProcessInfo
import OperInject
import sys
import QtFrame
from PyQt5.QtWidgets import QApplication


def ProcessCheckerView(ProcessInfo, OperInject):
    app = QApplication(sys.argv)
    form = QtFrame.Form()
    form.init_widget(ProcessInfo, OperInject)
    form.show()
    exit(app.exec_())


def main():
    obOperInject = OperInject.OperInject()
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning(obOperInject)

    ProcessCheckerView(obPInfo, obOperInject)


if __name__ == "__main__":
    main()
