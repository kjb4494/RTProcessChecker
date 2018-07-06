import ProcessInfo
import sys
import QtFrame
from PyQt5.QtWidgets import QApplication


def ProcessCheckerView(ProcessInfo):
    app = QApplication(sys.argv)
    form = QtFrame.Form()
    form.init_widget(ProcessInfo)
    form.show()
    exit(app.exec_())


def main():
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning()

    ProcessCheckerView(obPInfo)


if __name__ == "__main__":
    main()
