#!/bin/bash
echo "🎮 Minecraft Server Scanner"
echo "=========================="
echo ""
echo "Choose scanning mode:"
echo "1. Advanced scan (detailed info)"
echo "2. Quick scan (fast, basic info)"
echo "3. Custom IP range scan"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo "🚀 Starting advanced scan..."
        python3 main.py
        ;;
    2)
        echo "⚡ Starting quick scan..."
        python3 quick_scan.py
        ;;
    3)
        read -p "Enter IP range (e.g., 192.168.1.0/24): " range
        echo "🔍 Scanning custom range: $range"
        python3 -c "
import ipaddress, socket, threading
from queue import Queue

def check_ip(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((str(ip), 25565)) == 0:
            print(f'✅ {ip}:25565')
        sock.close()
    except: pass

def worker(q):
    while True:
        ip = q.get()
        if ip is None: break
        check_ip(ip)
        q.task_done()

network = ipaddress.IPv4Network('$range')
q = Queue()
for i in range(10):
    t = threading.Thread(target=worker, args=(q,))
    t.daemon = True
    t.start()

for ip in network.hosts():
    q.put(ip)
q.join()
"
        ;;
    *)
        echo "Invalid choice"
        ;;
esac
