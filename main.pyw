from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from Crypto.Cipher import AES
import base64
import pprint
import json
import os

BLOCK_SIZE = 16  # Bytes
def pad(s): return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
    chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def unpad(s): return s[:-ord(s[len(s) - 1:])]


def aesEncrypt(key, data):
    '''
    AES的ECB模式加密方法
    :param key: 密钥
    :param data:被加密字符串（明文）
    :return:密文
    '''
    key = key.encode('utf8')
    # 字符串补位
    data = pad(data)
    cipher = AES.new(key, AES.MODE_ECB)
    # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
    result = cipher.encrypt(data.encode())
    encodestrs = base64.b64encode(result)
    enctext = encodestrs.decode('utf8')
    # print(enctext)
    return enctext


class QSSLoader:
    def __init__(self):
        pass

    @staticmethod
    def read_qss_file(qss_file_name):
        with open(qss_file_name, 'r',  encoding='UTF-8') as file:
            return file.read()


style_sheet = QSSLoader.read_qss_file('style.qss')

def aesDecrypt(key, data):
    '''
    :param key: 密钥
    :param data: 加密后的数据（密文）
    :return:明文
    '''
    key = key.encode('utf8')
    data = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_ECB)

    # 去补位
    text_decrypted = unpad(cipher.decrypt(data))
    try:
        text_decrypted = text_decrypted.decode('utf8')
    except UnicodeDecodeError:
        return None
    # print(text_decrypted)
    return text_decrypted


class Setting(object):
    """
    a class of setting
    """
    set = {}

    # @overload
    def __init__(self, filename, name=None, value=None, mode='a'):
        """
        set `self.filename`, `self.text`, `self.mode`
        and set self.set
        """
        self.filename = filename
        self.mode = mode
        if not os.path.exists(filename):
            open(filename, 'w').close()
        self.io_r = open(filename, 'r')
        self.text = self.io_r.read()
        self.io_r.close()
        self.io = open(filename, self.mode)
        if self.text == '':
            return
        self.set = json.loads(self.text)
        if not name is None:
            for i in range(len(name)):
                self.set[name[i]] = value[i]

    def save(self):
        """
        save the dictionary in your file
        """
        s = json.dumps(self.set)
        with open(self.filename, 'w') as f:
            f.write(s)
        self.io = open(self.filename, self.mode)
        with open(self.filename) as f:
            self.text = f.read()

    def saveEnd(self):
        """
        Just save the setting, and close the file.
        """
        s = json.dumps(self.set)
        with open(self.filename, "w") as f:
            f.write(s)

    def set_dict(self, name, value):
        """
        :params `name`: a list of dict's key
        :params `value`: a list of dict's value
        :params `return`: none
        **this function will not save**
        **if len(name) != len(value), func will raise Error**
        """
        if len(name) != len(value):
            raise ValueError(
                f"The 'name' and 'value' must be the same length.")
        for i in range(len(value)):
            self.set[name[i]] = value[i]

    def append(self, dict):
        """
        :params `dict`: a dict you will append to the setting
        """
        for i in dict:
            self.set[i] = dict[i]

    def __len__(self):
        """
        :return the length of self.set
        """
        return len(self.set)

    def change(self, name, value):
        """
        change a value in self.set
        if it's not exists, it will be created
        """
        self.set[name] = value

    def get(self, name, default=None):
        """
        by dictionary's `get` function
        """
        return self.set.get(name, default)

    def clear(self):
        """
        clear all values and keys in self.set
        """
        self.set.clear()

    def delete(self, name):
        """
        delete a pair of value and key in self.set
        """
        del self.set[name]

    def memset(self, value):
        """
        like `memset` function in c++, but it will only set all values, not keys
        """
        for i in self.set:
            self.set[i] = value

    def print(self):
        """
        print all values and keys in self.set
        """
        pprint.pprint(self.set)

    def getKey(self):
        ret = [i for i in self.set]
        return ret

    def getValue(self):
        ret = [self.set[i] for i in self.set]
        return ret


class Psw:
    def __init__(self, keyn=None, filename='psw.json'):
        self.filename = filename
        self.setting = Setting(self.filename, mode='a')
        self.key = keyn
        if keyn is None:
            return
        if len(keyn) > 16:
            raise ValueError('Invalid key length')
        del keyn

    def setKey(self, keyn):
        if len(keyn) > 16:
            raise ValueError('Invalid key length')
        self.key = keyn
        for i in range(16 - len(keyn)):
            self.key += '0'  # 使用0补位
        del keyn

    def change(self, name, key, desc=None):
        self.setting.change(
            name, {'key': aesEncrypt(self.key, key), 'desc': desc})
        self.setting.save()

    def new(self, name, key, desc=None):
        self.setting.append(
            {name: {'key': aesEncrypt(self.key, key), 'desc': desc}})
        self.setting.save()

    def delete(self, name):
        self.setting.delete(name)
        self.setting.save()

    def encrypt(self, need, desc=None):
        return {
            'psw': aesDecrypt(self.key, self.setting.get(need)['key']),
            'desc': self.setting.get(need)['desc'],
            'name': need
        }

    def encryptAll(self):
        lst = [
            {
                'psw': aesDecrypt(self.key, self.setting.get(i)['key']),
                'desc': self.setting.get(i)['desc'],
                'name': i
            } for i in self.setting.getKey()
        ]
        return lst


class Ui_Widget(object):
    pswList = Psw(filename='psw.json')
    def setupUi(self, Widget):
        Widget.setObjectName("Widget")
        Widget.resize(760, 600)
        Widget.setStyleSheet(style_sheet)
        self.psw = QtWidgets.QLineEdit(Widget)
        self.psw.setGeometry(QtCore.QRect(10, 10, 261, 25))
        self.psw.setObjectName("psw")
        self.desc = QtWidgets.QTextEdit(Widget)
        self.desc.setGeometry(QtCore.QRect(10, 50, 261, 121))
        self.desc.setObjectName("desc")
        self.name = QtWidgets.QLineEdit(Widget)
        self.name.setGeometry(QtCore.QRect(290, 50, 201, 25))
        self.name.setObjectName("name")
        self.pswNeedRem = QtWidgets.QLineEdit(Widget)
        self.pswNeedRem.setGeometry(QtCore.QRect(510, 50, 241, 25))
        self.pswNeedRem.setObjectName("pswNeedRem")
        self.append = QtWidgets.QPushButton(Widget)
        self.append.setGeometry(QtCore.QRect(10, 190, 93, 29))
        self.append.setObjectName("append")
        self.lineEdit = QtWidgets.QLineEdit(Widget)
        self.lineEdit.setGeometry(QtCore.QRect(10, 240, 261, 25))
        self.lineEdit.setObjectName("lineEdit")
        self.ztl = QtWidgets.QTextEdit(Widget)
        self.ztl.setGeometry(QtCore.QRect(10, 330, 741, 221))
        self.ztl.setReadOnly(True)
        self.ztl.setObjectName("ztl")
        self.horizontalLayoutWidget = QtWidgets.QWidget(Widget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(10, 270, 221, 51))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.get = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.get.setObjectName("get")
        self.horizontalLayout.addWidget(self.get)
        self.getAll = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.getAll.setObjectName("getAll")
        self.horizontalLayout.addWidget(self.getAll)

        self.retranslateUi(Widget)
        QtCore.QMetaObject.connectSlotsByName(Widget)
        
        self.append.clicked.connect(self.appendAction)
        self.get.clicked.connect(self.get1)
        self.getAll.clicked.connect(self.getAllAction)

    def retranslateUi(self, Widget):
        _translate = QtCore.QCoreApplication.translate
        Widget.setWindowTitle(_translate("Widget", "Widget"))
        self.psw.setPlaceholderText(_translate("Widget", "获取psw的密码（无论如何都要填的）"))
        self.desc.setPlaceholderText(_translate("Widget", "描述（只有添加时才用）"))
        self.name.setPlaceholderText(_translate("Widget", "名字（例如哔哩哔哩账号）"))
        self.pswNeedRem.setPlaceholderText(_translate("Widget", "需记住的密码"))
        self.append.setText(_translate("Widget", "添加"))
        self.lineEdit.setPlaceholderText(_translate("Widget", "获取对象名字"))
        self.get.setText(_translate("Widget", "获取"))
        self.getAll.setText(_translate("Widget", "获取全部"))
    
    def appendAction(self):
        self.pswToAes = self.psw.text()
        self.pswList.setKey(self.pswToAes)
        self.pswList.new(self.name.text(),
                         self.pswNeedRem.text(), self.desc.toPlainText())
        self.pswNeedRem.clear()
    
    def get1(self):
        self.getName = self.lineEdit.text()
        self.pswToAes = self.psw.text()
        self.pswList.setKey(self.pswToAes)
        self.youNeed = self.pswList.encrypt(self.getName)
        self.ztl.insertHtml(f"<>名字为：{self.youNeed['name']}，密码为：{self.youNeed['psw']}，描述为：{self.youNeed['desc']}\n")
    
    def getAllAction(self):
        self.ztl.clear()
        self.getName = self.lineEdit.text()
        self.pswToAes = self.psw.text()
        self.pswList.setKey(self.pswToAes)
        self.youNeed = self.pswList.encryptAll()
        for i in self.youNeed:
            self.ztl.append(
                f"名字为：{i['name']}，密码为：{i['psw']}，描述为：{i['desc']}\n")


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_Widget()

    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
