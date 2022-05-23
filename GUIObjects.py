from PyQt5 import QtWidgets, QtCore, QtGui


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, on_exit, on_connect):
        super().__init__()

        self.setWindowTitle("My App")
        widget = QtWidgets.QWidget()
        self.setCentralWidget(widget)


        connect_button = QtWidgets.QPushButton("Connect")
        connect_button.clicked.connect(on_connect)

        exit_button = QtWidgets.QPushButton("Exit")
        exit_button.clicked.connect(on_exit)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(connect_button)
        layout.addWidget(exit_button)
        widget.setLayout(layout)