import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import socket
import struct
import time
import threading
import csv
import json
from tkinter import filedialog


packets = []  # Lista para armazenar os pacotes capturados

def capture_packets():
    # Interface de rede para captura (use sua interface de rede aqui, por exemplo: 'eth0', 'wlan0')
    interface = "wlan0"
    
    # Criar um socket para captura de pacotes
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((interface, 0))

    while True:
        raw_packet = s.recv(65535) 
        process_packet(raw_packet)

def process_packet(packet):
    timestamp = time.time()
    eth_header = packet[:14]
    eth_data = struct.unpack("!6s6sH", eth_header)
    eth_protocol = socket.ntohs(eth_data[2])

    if eth_protocol == 8:  # Se for pacote IPv4
        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        if protocol == 6:  # TCP
            tcp_header = packet[34:54]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            src_port = tcph[0]
            dest_port = tcph[1]
            packets.append({"timestamp": timestamp, "protocol": "TCP", "src_ip": src_ip, "dest_ip": dest_ip, "src_port": src_port, "dest_port": dest_port})
        elif protocol == 17:  # UDP
            udp_header = packet[34:42]
            udph = struct.unpack("!HHHH", udp_header)
            src_port = udph[0]
            dest_port = udph[1]
            packets.append({"timestamp": timestamp, "protocol": "UDP", "src_ip": src_ip, "dest_ip": dest_ip, "src_port": src_port, "dest_port": dest_port})

# Função para atualizar gráfico
def update_graph(i):
    if len(packets) > 0:
        times = [packet["timestamp"] for packet in packets]
        tcp_count = sum(1 for packet in packets if packet["protocol"] == "TCP")
        udp_count = sum(1 for packet in packets if packet["protocol"] == "UDP")

        ax.clear()
        ax.plot(times, [tcp_count] * len(times), label="TCP", color="blue")
        ax.plot(times, [udp_count] * len(times), label="UDP", color="red")
        ax.legend()
        ax.set_xlabel("Tempo (segundos)")
        ax.set_ylabel("Contagem de pacotes")
        ax.set_title("Contagem de pacotes TCP/UDP")

    canvas.draw()

# Função para criar a interface gráfica
def create_gui():
    global root, canvas, ax, fig

    root = tk.Tk()
    root.title("Sniffer de Rede")

    # Criar a figura e o gráfico
    fig, ax = plt.subplots(figsize=(8, 6))

    # Criar o canvas para renderizar o gráfico no Tkinter
    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.get_tk_widget().pack(pady=20)

    # Botões e outros elementos da interface
    start_button = tk.Button(root, text="Iniciar Captura", command=start_capture)
    start_button.pack()

    stop_button = tk.Button(root, text="Parar Captura", command=root.quit)
    stop_button.pack()

    save_button = tk.Button(root, text="Salvar Relatório", command=save_report)
    save_button.pack()

    # Função de animação do gráfico
    ani = FuncAnimation(fig, update_graph, interval=1000)  # Atualiza o gráfico a cada segundo

    root.mainloop()

# Função para iniciar a captura em uma thread
def start_capture():
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True
    capture_thread.start()

# Função para salvar o relatório em CSV ou JSON
def save_report():
    # Opção para escolher onde salvar o arquivo
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
    if file_path:
        if file_path.endswith(".csv"):
            save_to_csv(file_path)
        elif file_path.endswith(".json"):
            save_to_json(file_path)

# Função para salvar em formato CSV
def save_to_csv(file_path):
    keys = ["timestamp", "protocol", "src_ip", "dest_ip", "src_port", "dest_port"]
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        for packet in packets:
            writer.writerow(packet)

# Função para salvar em formato JSON
def save_to_json(file_path):
    with open(file_path, mode='w') as file:
        json.dump(packets, file, indent=4)

# Iniciar a interface gráfica
create_gui()
