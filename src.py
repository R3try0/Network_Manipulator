import sys
import subprocess
import platform
import os, re, csv
import winreg
from PyQt6 import QtWidgets, QtGui, QtCore
import socket
import psutil
from datetime import datetime
from scapy.all import srp, ARP, Ether, conf

interf = "Sexy Beast"
def set_mac_in_all_registry_keys(new_mac):
    try:
        # Normalize MAC address
        normalized_mac = re.sub(r'[^0-9A-Fa-f]', '', new_mac).upper()
        if len(normalized_mac) != 12:
            raise ValueError("Invalid MAC format: must be exactly 12 hexadecimal digits")

        # Update keys under Tcpip\Parameters\Interfaces
        tcpip_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tcpip_path, 0, winreg.KEY_READ) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                subkey_path = f"{tcpip_path}\\{subkey_name}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_SET_VALUE) as subkey:
                        winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, normalized_mac)
                except Exception as e:
                    print(f"Failed to set MAC in {subkey_path}: {e}")

        # Update keys under Class\{4d36e972-e325-11ce-bfc1-08002be10318}
        class_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, class_path, 0, winreg.KEY_READ) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                subkey_path = f"{class_path}\\{subkey_name}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_SET_VALUE) as subkey:
                        winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, normalized_mac)
                except Exception as e:
                    print(f"Failed to set MAC in {subkey_path}: {e}")

        print("MAC address updated in all relevant registry keys.")
    except Exception as e:
        print(f"Error updating MAC address in registry: {e}")

def find_vendor_by_mac(mac_address, csv_file='mac_vendors.csv'):
    cleaned_mac = re.sub(r'[^0-9A-Fa-f]', '', mac_address).upper()
    prefix = cleaned_mac[:6]
    with open(csv_file, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) >= 2:
                csv_prefix = row[0].strip().upper()
                vendor = row[1].strip()
                if csv_prefix == prefix:
                    return vendor
    return "Unknown Vendor"

def get_active_interface():
    iface, local_ip, _ = conf.route.route("0.0.0.0")
    return iface, local_ip

def get_name_active_interface():
    scapy_iface, local_ip, _ = conf.route.route("0.0.0.0")
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                return name, local_ip
    return scapy_iface, local_ip

def arp_scan(interface, network):
    conf.verb = 0
    hosts, macs = [], []
    start = datetime.now()
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        timeout=5, iface=interface, inter=0.1
    )
    for _, rcv in ans:
        hosts.append(rcv.psrc)
        macs.append(rcv.src)
    return hosts, macs, (datetime.now() - start).total_seconds()

def get_default_adapter():
    try:
        scapy_iface, active_ip = get_active_interface()
        if not active_ip or active_ip == '0.0.0.0':
            raise RuntimeError("No active IP address found.")
        interfaces = psutil.net_if_addrs()
        for name, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == active_ip:
                    friendly_name = name
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces")
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            ip_value, _ = winreg.QueryValueEx(subkey, "DhcpIPAddress")
                            if ip_value == active_ip:
                                return friendly_name, subkey_name
                        except FileNotFoundError:
                            try:
                                ip_value_static = winreg.QueryValueEx(subkey, "IPAddress")[0]
                                if active_ip in ip_value_static.split(','):
                                    return friendly_name, subkey_name
                            except FileNotFoundError:
                                continue
                    raise RuntimeError("No matching Tcpip interface found for active IP in registry.")
        raise RuntimeError("No interface found with active IP address.")
    except Exception as e:
        raise RuntimeError(f"Failed to find default adapter: {str(e)}")

def restart_adapter(interface_name):
    subprocess.check_call(f'netsh interface set interface name="{interface_name}" admin=disabled', shell=True)
    subprocess.check_call(f'netsh interface set interface name="{interface_name}" admin=enabled', shell=True)
    subprocess.check_call("ipconfig /renew", shell=True)

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(781, 571)
        Dialog.setFixedSize(781, 571)
        self.progressBar = QtWidgets.QProgressBar(parent=Dialog)
        self.progressBar.setGeometry(QtCore.QRect(10, 230, 291, 23))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.label = QtWidgets.QLabel(parent=Dialog)
        self.label.setGeometry(QtCore.QRect(10, 20, 121, 16))
        self.label.setObjectName("label")
        self.pushButton = QtWidgets.QPushButton(parent=Dialog)
        self.pushButton.setGeometry(QtCore.QRect(300, 230, 100, 23))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(parent=Dialog)
        self.pushButton_2.setGeometry(QtCore.QRect(420, 230, 100, 23))
        self.pushButton_2.setObjectName("pushButton_2")
        self.lineEdit = QtWidgets.QLineEdit(parent=Dialog)
        self.lineEdit.setGeometry(QtCore.QRect(530, 230, 201, 20))
        self.lineEdit.setObjectName("lineEdit")
        self.pushButton_3 = QtWidgets.QPushButton(parent=Dialog)
        self.pushButton_3.setGeometry(QtCore.QRect(560, 540, 101, 23))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(parent=Dialog)
        self.pushButton_4.setGeometry(QtCore.QRect(670, 540, 101, 23))
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_5 = QtWidgets.QPushButton(parent=Dialog)
        self.pushButton_5.setGeometry(QtCore.QRect(420, 540, 131, 23))
        self.pushButton_5.setObjectName("pushButton_5")
        
        # New button to manually update interface information
        self.pushButton_update_interfaces = QtWidgets.QPushButton(parent=Dialog)
        self.pushButton_update_interfaces.setGeometry(QtCore.QRect(10, 540, 150, 23))
        self.pushButton_update_interfaces.setObjectName("pushButton_update_interfaces")
        
        self.tableWidget = QtWidgets.QTableWidget(parent=Dialog)
        self.tableWidget.setGeometry(QtCore.QRect(10, 41, 741, 181))
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setRowCount(0)
        headers = ["IP Address", "MAC Address", "Device Type", "Interface"]
        self.tableWidget.setHorizontalHeaderLabels(headers)
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.tableWidget.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.tableWidget_2 = QtWidgets.QTableWidget(parent=Dialog)
        self.tableWidget_2.setGeometry(QtCore.QRect(10, 290, 741, 241))
        self.tableWidget_2.setObjectName("tableWidget_2")
        self.tableWidget_2.setColumnCount(3)
        self.tableWidget_2.setRowCount(0)
        headers2 = ["Interface", "IP Address", "MAC Address"]
        self.tableWidget_2.setHorizontalHeaderLabels(headers2)
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Network Scanner"))
        self.label.setText(_translate("Dialog", "All Connected Devices"))
        self.pushButton.setText(_translate("Dialog", "Scan Devices"))
        self.pushButton_2.setText(_translate("Dialog", "Change MAC"))
        self.lineEdit.setPlaceholderText(_translate("Dialog", "Enter new MAC..."))
        self.pushButton_3.setText(_translate("Dialog", "Quit without Save"))
        self.pushButton_4.setText(_translate("Dialog", "Quit with Save"))
        self.pushButton_5.setText(_translate("Dialog", "Save MAC Addresses"))
        self.pushButton_update_interfaces.setText(_translate("Dialog", "Update Interfaces"))  # New button text


class MainApp(QtWidgets.QDialog, Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.scan_devices)
        self.pushButton_2.clicked.connect(self.change_mac)
        self.pushButton_5.clicked.connect(self.save_mac_addresses)
        self.pushButton_3.clicked.connect(self.quit_no_save)
        self.pushButton_4.clicked.connect(self.quit_with_save)
        self.pushButton_update_interfaces.clicked.connect(self.populate_interfaces)  # Connect new button to populate_interfaces
        self.tableWidget.customContextMenuRequested.connect(self.show_context_menu)
        self.populate_interfaces()

    def scan_devices(self):
        self.progressBar.setValue(0)
        self.progressBar.setValue(10)
        QtWidgets.QApplication.processEvents()
        scapy_iface, ip = get_active_interface()
        friendly_iface, _ = get_name_active_interface()
        global interf
        interf = friendly_iface
        if not scapy_iface or not ip:
            QtWidgets.QMessageBox.critical(self, "Error", "No active interface found.")
            self.progressBar.setValue(0)
            return
        self.progressBar.setValue(30)
        QtWidgets.QApplication.processEvents()
        network = f"{ip}/24"
        hosts, macs, duration = arp_scan(scapy_iface, network)
        self.progressBar.setValue(60)
        QtWidgets.QApplication.processEvents()
        vendors = []
        for mac in macs:
            try:
                vendors.append(find_vendor_by_mac(mac))
            except Exception:
                vendors.append("Unknown Vendor")
        self.progressBar.setValue(80)
        QtWidgets.QApplication.processEvents()
        self.tableWidget.setRowCount(len(hosts))
        for i, (h, m, v) in enumerate(zip(hosts, macs, vendors)):
            self.tableWidget.setItem(i, 0, QtWidgets.QTableWidgetItem(h))
            self.tableWidget.setItem(i, 1, QtWidgets.QTableWidgetItem(m))
            self.tableWidget.setItem(i, 2, QtWidgets.QTableWidgetItem(v))
            self.tableWidget.setItem(i, 3, QtWidgets.QTableWidgetItem(interf))
        self.progressBar.setValue(100)
        QtWidgets.QApplication.processEvents()

    def change_mac(self):
        new_mac = self.lineEdit.text().strip()
        friendly_iface, _ = get_name_active_interface()
        if not new_mac:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a valid MAC address.")
            return

        normalized_mac = re.sub(r'[^0-9A-Fa-f]', '', new_mac).upper()

        if len(normalized_mac) != 12:
            QtWidgets.QMessageBox.warning(self, "Invalid Format", "MAC address must have 12 hexadecimal characters.")
            return

        os_name = platform.system()
        try:
            if os_name == 'Linux':
                iface, _ = get_active_interface()
                subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', iface, 'down'], check=True)
                subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', iface, 'address', normalized_mac], check=True)
                subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', iface, 'up'], check=True)
            elif os_name == 'Darwin':
                iface, _ = get_active_interface()
                subprocess.run(['sudo', 'ifconfig', iface, 'ether', normalized_mac], check=True)
            elif os_name == 'Windows':
                set_mac_in_all_registry_keys(normalized_mac)  # Use the existing function
                restart_adapter(friendly_iface)  # Restart the adapter to apply changes
            else:
                QtWidgets.QMessageBox.information(self, "Unsupported", f"MAC change not supported on {os_name}.")
                return
            QtWidgets.QMessageBox.information(self, "Success", subprocess.check_output(["getmac", "/v"], text=True, shell=True))
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to change MAC address: {e}")

        # Refresh the interface table after changing the MAC address
        self.populate_interfaces()

    def save_mac_addresses(self):
        path = QtWidgets.QFileDialog.getSaveFileName(self, 'Save File', '', 'Text Files (*.txt)')[0]
        if not path:
            return
        with open(path, "w") as f:
            for row in range(self.tableWidget.rowCount()):
                ip = self.tableWidget.item(row, 0).text()
                mac = self.tableWidget.item(row, 1).text()
                f.write(f"IP: {ip}, MAC: {mac}\n")
        QtWidgets.QMessageBox.information(self, "Saved", "MAC addresses saved successfully.")

    def quit_no_save(self):
        self.close()

    def quit_with_save(self):
        self.save_mac_addresses()
        self.close()

    def populate_interfaces(self):
        interfaces = psutil.net_if_addrs()
        self.tableWidget_2.setRowCount(len(interfaces))
        for i, (name, addrs) in enumerate(interfaces.items()):
            ip = next((a.address for a in addrs if a.family == socket.AF_INET), "N/A")
            mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), "N/A")
            self.tableWidget_2.setItem(i, 0, QtWidgets.QTableWidgetItem(name))
            self.tableWidget_2.setItem(i, 1, QtWidgets.QTableWidgetItem(ip))
            self.tableWidget_2.setItem(i, 2, QtWidgets.QTableWidgetItem(mac))

    def show_context_menu(self, pos):
        item = self.tableWidget.itemAt(pos)
        if item and item.column() == 1:
            menu = QtWidgets.QMenu(self)
            copy_action = menu.addAction("Copy MAC to input")
            action = menu.exec(self.tableWidget.mapToGlobal(pos))
            if action == copy_action:
                QtWidgets.QApplication.clipboard().setText(item.text())
                self.lineEdit.setText(item.text())

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec())