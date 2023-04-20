import sys
from PyQt5 import QtCore, QtGui, QtWidgets, uic
from findDLL import *
from helper import *
pyQTfileName = "test_ui.ui"

Ui_MainWindow, QtBaseClass = uic.loadUiType(pyQTfileName)

##radioButtons = dict()


class MyApp(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        ##super().__init__()
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        #self.resize(300,1000)
        #self.resize(200,200)

        findDLLStrings()
        load_strings()
        result = search_calls()
        load_dlls()
        # msgbox = QMessageBox()
        text = ''
        if is_suspicious(result) and pattern_match(result) and len(custom_dlls) > 0:
            print('Warning: Your Binary Might Cause Potential DLL Injection')
            text += 'Custom DLLs found \n'
            for s in custom_dlls:
                text+=s+'\n'
            text+= 'Warning: Your Binary Might Cause Potential DLL Injection\n'
        else:
            print('found nothing')
            text+='Nothing suspicious found\n'
        text+='\n\n'
        text+='Additional Information: System DLLs\n'
        for s in system_dlls:
            text+=s+'\n'
        self.label.setText(text)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())
