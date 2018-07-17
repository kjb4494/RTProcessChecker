#!/usr/bin/env python
# coding: utf-8

# 예제 내용
# * 기본 위젯을 사용하여 기본 창을 생성
# * 다양한 레이아웃 위젯 사용

import sys

from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QLabel
from PyQt5.QtWidgets import QSpacerItem
from PyQt5.QtWidgets import QLineEdit
from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtWidgets import QPushButton
from PyQt5.QtWidgets import QGroupBox

from PyQt5.QtWidgets import QBoxLayout
from PyQt5.QtWidgets import QHBoxLayout
from PyQt5.QtWidgets import QVBoxLayout

from PyQt5.QtWidgets import QGridLayout
from PyQt5.QtWidgets import QFormLayout

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTreeWidgetItem
from PyQt5.QtWidgets import QTreeWidget

__author__ = "Deokyu Lim <hong18s@gmail.com>"


class Form(QWidget):
    def __init__(self):
        QWidget.__init__(self, flags=Qt.Widget)

        self.setWindowTitle("Various Layout Widgets")
        #self.setFixedWidth(640)
        #.setFixedHeight(480)
        self.setGeometry(600, 200, 600, 600)
        layout_base = QBoxLayout(QBoxLayout.TopToBottom, self)
        self.setLayout(layout_base)


        self.tw = QTreeWidget()
        self.ew = QTextEdit()
        # 첫 번째 그룹
        grp_1 = QGroupBox()
        layout_base.addWidget(grp_1)
        layout = QGridLayout()
        layout.addWidget(self.tw, 0, 0)
        layout.addWidget(self.ew, 1, 0)
        layout.setRowStretch(0, 4)
        layout.setRowStretch(1, 1)
        grp_1.setLayout(layout)

        # 두 번째 그룹
        #grp_2 = QGroupBox("Log")
        #layout_base.addWidget(grp_2)
        #layout = QGridLayout()
        #layout.addWidget(self.ew)
        #layout.setRowStretch(1, 1)
        #grp_2.setLayout(layout)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    form = Form()
    form.show()
    exit(app.exec_())