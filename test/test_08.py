from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QTreeWidget
from PyQt5.QtCore import QVariant
from PyQt5.QtWidgets import QTreeWidgetItem
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QThread
from PyQt5.QtCore import pyqtSignal


class TableWidget(QTableWidget):
    cellExited = QtCore.pyqtSignal(int, int)
    itemExited = QtCore.pyqtSignal(QtGui.QTableWidgetItem)

    def __init__(self, rows, columns, parent=None):
        QtGui.QTableWidget.__init__(self, rows, columns, parent)
        self._last_index = QtCore.QPersistentModelIndex()
        self.viewport().installEventFilter(self)

    def eventFilter(self, widget, event):
        if widget is self.viewport():
            index = self._last_index
            if event.type() == QtCore.QEvent.MouseMove:
                index = self.indexAt(event.pos())
            elif event.type() == QtCore.QEvent.Leave:
                index = QtCore.QModelIndex()
            if index != self._last_index:
                row = self._last_index.row()
                column = self._last_index.column()
                item = self.item(row, column)
                if item is not None:
                    self.itemExited.emit(item)
                self.cellExited.emit(row, column)
                self._last_index = QtCore.QPersistentModelIndex(index)
        return QtGui.QTableWidget.eventFilter(self, widget, event)

class Window(QtGui.QWidget):
    def __init__(self, rows, columns):
        QtGui.QWidget.__init__(self)
        self.table = TableWidget(rows, columns, self)
        for column in range(columns):
            for row in range(rows):
                item = QtGui.QTableWidgetItem('Text%d' % row)
                self.table.setItem(row, column, item)
        layout = QtGui.QVBoxLayout(self)
        layout.addWidget(self.table)
        self.table.setMouseTracking(True)
        self.table.itemEntered.connect(self.handleItemEntered)
        self.table.itemExited.connect(self.handleItemExited)

    def handleItemEntered(self, item):
        item.setBackground(QtGui.QColor('moccasin'))

    def handleItemExited(self, item):
        item.setBackground(QtGui.QTableWidgetItem().background())

if __name__ == '__main__':

    import sys
    app = QtGui.QApplication(sys.argv)
    window = Window(6, 3)
    window.setGeometry(500, 300, 350, 250)
    window.show()
    sys.exit(app.exec_())