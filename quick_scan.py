#!/usr/bin/env python3
"""
Quick and dirty Minecraft server finder
Scans common IP ranges and outputs working servers
"""
import socket
import threading
import time
import random
import json
from queue import Queue

class QuickMCScanner:
    def __init__(self):
        self.found = []
        self.scanned = 0
        
    def check_server(self, ip, port=25565):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start = time.time()
            
            if sock.connect_ex((ip, port)) == 0:
                # Send basic ping
                sock.send(b'\x00\x00')
                response = sock.recv(1024)
                ping = int((time.time() - start) * 1000)
                sock.close()
                
                if response:
                    return {'ip': ip, 'port': port, 'ping': ping}
            sock.close()
        except:
            pass
        return None
    
    def worker(self, q):
        while True:
            ip = q.get()
            if ip is None:
                break
                
            # Try common MC ports
            for port in [25565, 25566, 25567]:
                result = self.check_server(ip, port)
                if result:
                    self.found.append(result)
                    print(f"✅ {ip}:{port} - {result['ping']}ms")
                    break
            
            self.scanned += 1
            if self.scanned % 100 == 0:
                print(f"Scanned: {self.scanned}, Found: {len(self.found)}")
            
            q.task_done()
    
    def scan(self):
        # Generate IPs from common ranges
        ips = []
        ranges = [
            (147, 135, 0, 255),    # OVH
            (51, 68, 0, 255),      # OVH
            (167, 114, 0, 255),    # OVH
            (198, 27, 64, 127),    # Hetzner
            (116, 202, 0, 255),    # Hetzner
        ]
        
        for a, b, c_start, c_end in ranges:
            for c in range(c_start, min(c_start + 5, c_end + 1)):  # Limit range
                for d in random.sample(range(1, 255), 50):  # Random IPs
                    ips.append(f"{a}.{b}.{c}.{d}")
        
        print(f"🔍 Scanning {len(ips)} IPs for Minecraft servers...")
        
        # Multi-threaded scanning
        q = Queue()
        threads = []
        
        # Start workers
        for i in range(20):
            t = threading.Thread(target=self.worker, args=(q,))
            t.start()
            threads.append(t)
        
        # Add IPs to queue
        for ip in ips:
            q.put(ip)
        
        # Wait for completion
        q.join()
        
        # Stop workers
        for i in range(20):
            q.put(None)
        for t in threads:
            t.join()
        
        print(f"\n🎯 Scan complete! Found {len(self.found)} servers:")
        for server in sorted(self.found, key=lambda x: x['ping']):
            print(f"   {server['ip']}:{server['port']} ({server['ping']}ms)")

if __name__ == "__main__":
    scanner = QuickMCScanner()
    scanner.scan()
