import sys
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QTableWidget, QTableWidgetItem, QTextEdit
from PyQt5.QtCore import Qt
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pyqtgraph as pg

class NetworkTrafficAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

        # Initialize variables
        self.capture = None
        self.filter = ''
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_data = []

        # Setup matplotlib for real-time graph
        self.fig, self.ax = plt.subplots()
        self.line, = self.ax.plot([], [], lw=2)
        self.x_data, self.y_data = [], []
        self.ani = FuncAnimation(self.fig, self.update_graph, init_func=self.init_graph, blit=True, cache_frame_data=False)

    def initUI(self):
        self.setWindowTitle('Network Traffic Analyzer')
        self.setGeometry(100, 100, 1000, 700)

        layout = QVBoxLayout()

        # Start/Stop capture buttons
        self.start_button = QPushButton('Start Capture', self)
        self.start_button.clicked.connect(self.toggleCapture)
        layout.addWidget(self.start_button)

        # Filter input
        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText('Enter packet filter (e.g., "tcp", "udp", "icmp")')
        layout.addWidget(self.filter_input)

        # Protocol statistics display
        self.protocol_label = QLabel('TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0', self)
        layout.addWidget(self.protocol_label)

        # Graph for live data visualization
        self.graph_widget = pg.PlotWidget()
        self.graph_data = self.graph_widget.plot()
        layout.addWidget(self.graph_widget)

        # Packet details table
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length'])
        layout.addWidget(self.packet_table)

        # Log area for warnings/errors
        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

    def toggleCapture(self):
        if self.capture is None:
            self.startCapture()
        else:
            self.stopCapture()

    def startCapture(self):
        self.filter = self.filter_input.text()
        self.capture = scapy.AsyncSniffer(prn=self.process_packet, filter=self.filter, store=False)
        self.capture.start()
        self.start_button.setText('Stop Capture')

    def stopCapture(self):
        if self.capture is not None:
            self.capture.stop()
            self.capture = None
            self.start_button.setText('Start Capture')

    def process_packet(self, packet):
        self.total_packets += 1
        self.total_bytes += len(packet)
        self.packet_data.append(packet)

        # Update protocol statistics
        if packet.haslayer(TCP):
            self.protocol_stats['TCP'] += 1
            if not self.validate_checksum(packet[TCP]):
                self.log_area.append("Invalid TCP checksum detected")
        elif packet.haslayer(UDP):
            self.protocol_stats['UDP'] += 1
            if not self.validate_checksum(packet[UDP]):
                self.log_area.append("Invalid UDP checksum detected")
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
        else:
            self.protocol_stats['Other'] += 1

        # Update the protocol label in the UI
        self.protocol_label.setText(
            f"TCP: {self.protocol_stats['TCP']} | UDP: {self.protocol_stats['UDP']} | ICMP: {self.protocol_stats['ICMP']} | Other: {self.protocol_stats['Other']}"
        )

        # Add packet details to the table
        self.addPacketToTable(packet)

        # Update live data visualization
        self.update_graph()

    def validate_checksum(self, packet_layer):
        # Placeholder function for checksum validation
        return True  # Needs proper implementation based on Scapy or external libraries

    def addPacketToTable(self, packet):
        timestamp = packet.time
        src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'
        protocol = packet.proto if packet.haslayer(IP) else 'N/A'
        length = len(packet)

        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(timestamp)))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(src_ip))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(dst_ip))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(str(protocol)))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(str(length)))

    def init_graph(self):
        self.ax.set_xlim(0, 10)
        self.ax.set_ylim(0, 1000)  # Adjust the y-axis limit as needed
        self.ax.set_xlabel('Time (s)')
        self.ax.set_ylabel('Bytes')
        self.ax.set_title('Network Traffic Over Time')
        return self.line,

    def update_graph(self, frame=None):
        if len(self.x_data) == 0:
            self.x_data.append(0)
        else:
            self.x_data.append(self.x_data[-1] + 1)

        self.y_data.append(self.total_bytes)

        # Ensure x_data and y_data are of the same length
        min_len = min(len(self.x_data), len(self.y_data))
        self.x_data = self.x_data[:min_len]
        self.y_data = self.y_data[:min_len]

        self.graph_data.setData(self.x_data, self.y_data)
        self.line.set_data(self.x_data, self.y_data)
        self.ax.relim()
        self.ax.autoscale_view()
        return self.line,

    def closeEvent(self, event):
        self.stopCapture()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    analyzer = NetworkTrafficAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())
