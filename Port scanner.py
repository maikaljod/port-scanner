import sys
import socket
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QProgressBar,
    QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class PortScanner(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()

    def __init__(self, target, start_port, end_port, timeout=1):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.running = True

    def run(self):
        try:
            target_ip = socket.gethostbyname(self.target)
            self.update_signal.emit(f"Scanning target: {target_ip}\n")
            
            total_ports = self.end_port - self.start_port + 1
            scanned_ports = 0
            
            for port in range(self.start_port, self.end_port + 1):
                if not self.running:
                    break
                    
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    self.update_signal.emit(f"Port {port} ({service}) is open")
                
                sock.close()
                
                scanned_ports += 1
                progress = int((scanned_ports / total_ports) * 100)
                self.progress_signal.emit(progress)
                
        except socket.gaierror:
            self.update_signal.emit("Hostname could not be resolved")
        except socket.error:
            self.update_signal.emit("Could not connect to server")
        finally:
            self.finished_signal.emit()

    def stop(self):
        self.running = False

class PortScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Port Scanner")
     
     
        self.setGeometry(100, 100, 500, 400)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit("localhost")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # Port range inputs
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Start Port:"))
        self.start_port_input = QLineEdit("1")
        self.start_port_input.setMaximumWidth(80)
        port_layout.addWidget(self.start_port_input)
        
        port_layout.addWidget(QLabel("End Port:"))
        self.end_port_input = QLineEdit("1024")
        self.end_port_input.setMaximumWidth(80)
        port_layout.addWidget(self.end_port_input)
        
        port_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_input = QLineEdit("1")
        self.timeout_input.setMaximumWidth(50)
        port_layout.addWidget(self.timeout_input)
        layout.addLayout(port_layout)
        
        # Scan button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # Stop button
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        layout.addWidget(self.results_display)
        
        # Scanner thread
        self.scanner = None

    def start_scan(self):
        try:
            target = self.target_input.text()
            start_port = int(self.start_port_input.text())
            end_port = int(self.end_port_input.text())
            timeout = float(self.timeout_input.text())
            
            if start_port < 1 or start_port > 65535:
                raise ValueError("Start port must be between 1 and 65535")
            if end_port < 1 or end_port > 65535:
                raise ValueError("End port must be between 1 and 65535")
            if end_port < start_port:
                raise ValueError("End port must be greater than or equal to start port")
            if timeout <= 0:
                raise ValueError("Timeout must be greater than 0")
                
            self.results_display.clear()
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            self.scanner = PortScanner(target, start_port, end_port, timeout)
            self.scanner.update_signal.connect(self.update_results)
            self.scanner.progress_signal.connect(self.update_progress)
            self.scanner.finished_signal.connect(self.scan_finished)
            self.scanner.start()
            
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", str(e))

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.scanner.wait()
            self.results_display.append("\nScan stopped by user")

    def update_results(self, text):
        self.results_display.append(text)

    def update_progress(self, value):

        
        self.progress_bar.setValue(value)

    def scan_finished(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.results_display.append("\nScan completed")
        self.scanner = None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortScannerGUI()
    window.show()
    sys.exit(app.exec_())