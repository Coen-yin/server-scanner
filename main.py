#!/usr/bin/env python3
import asyncio
import socket
import struct
import json
import time
import random
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional
import ipaddress

class MinecraftScanner:
    def __init__(self):
        self.found_servers = []
        self.timeout = 3
        
    def create_handshake_packet(self, host: str, port: int) -> bytes:
        """Create Minecraft handshake packet"""
        # Packet structure for server list ping
        packet_id = b'\x00'  # Handshake packet ID
        protocol_version = b'\x47'  # Protocol version (71 for 1.6+)
        server_address_length = len(host).to_bytes(1, 'big')
        server_address = host.encode('utf-8')
        server_port = struct.pack('>H', port)
        next_state = b'\x01'  # Status request
        
        # Build packet
        data = packet_id + protocol_version + server_address_length + server_address + server_port + next_state
        length = len(data).to_bytes(1, 'big')
        
        return length + data
    
    def check_minecraft_server(self, ip: str, port: int = 25565) -> Optional[dict]:
        """Check if IP:port is a Minecraft server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                start_time = time.time()
                
                # Try to connect
                result = sock.connect_ex((ip, port))
                if result != 0:
                    return None
                
                # Send handshake
                handshake = self.create_handshake_packet(ip, port)
                sock.send(handshake)
                
                # Send status request
                status_request = b'\x01\x00'  # Length + Status Request packet
                sock.send(status_request)
                
                # Read response
                response = sock.recv(4096)
                ping = int((time.time() - start_time) * 1000)
                
                if len(response) > 5:
                    try:
                        # Parse JSON response
                        json_start = response.find(b'{')
                        if json_start != -1:
                            json_data = response[json_start:].decode('utf-8', errors='ignore')
                            # Find the end of JSON
                            brace_count = 0
                            json_end = 0
                            for i, char in enumerate(json_data):
                                if char == '{':
                                    brace_count += 1
                                elif char == '}':
                                    brace_count -= 1
                                    if brace_count == 0:
                                        json_end = i + 1
                                        break
                            
                            if json_end > 0:
                                server_info = json.loads(json_data[:json_end])
                                return {
                                    'ip': ip,
                                    'port': port,
                                    'ping': ping,
                                    'version': server_info.get('version', {}).get('name', 'Unknown'),
                                    'protocol': server_info.get('version', {}).get('protocol', 0),
                                    'players': server_info.get('players', {}),
                                    'description': server_info.get('description', {}),
                                    'online': True
                                }
                    except:
                        pass
                
                # If we got here, it responded but not with valid MC data
                return {
                    'ip': ip,
                    'port': port,
                    'ping': ping,
                    'version': 'Unknown',
                    'online': True,
                    'raw_response': True
                }
                
        except Exception as e:
            return None
    
    def generate_common_ips(self) -> List[str]:
        """Generate list of common Minecraft server IPs"""
        ips = []
        
        # Common hosting provider ranges
        ranges = [
            "147.135.0.0/20",   # OVH
            "51.68.0.0/20",     # OVH  
            "167.114.0.0/20",   # OVH
            "198.27.64.0/20",   # Hetzner
            "116.202.0.0/20",   # Hetzner
            "5.9.0.0/18",       # Hetzner
            "144.76.0.0/16",    # Hetzner
            "78.46.0.0/15",     # Hetzner
            "88.99.0.0/16",     # Hetzner
            "159.69.0.0/16",    # Hetzner
            "95.216.0.0/16",    # Hetzner
            "135.181.0.0/16",   # Hetzner
        ]
        
        for range_str in ranges:
            network = ipaddress.IPv4Network(range_str)
            # Sample random IPs from each range
            hosts = list(network.hosts())
            sample_size = min(1000, len(hosts))  # Limit per range
            sampled = random.sample(hosts, sample_size)
            ips.extend([str(ip) for ip in sampled])
        
        return ips
    
    def scan_ip_batch(self, ip_batch: List[str]) -> List[dict]:
        """Scan a batch of IPs"""
        results = []
        for ip in ip_batch:
            # Check common Minecraft ports
            for port in [25565, 25566, 25567, 25568, 25569, 25570]:
                server_info = self.check_minecraft_server(ip, port)
                if server_info:
                    results.append(server_info)
                    print(f"✅ FOUND: {ip}:{port} - {server_info.get('version', 'Unknown')} - {server_info['ping']}ms")
                    break  # Found one, move to next IP
        return results
    
    async def scan_async(self, max_workers: int = 50):
        """Scan for Minecraft servers asynchronously"""
        print("🔍 Generating IP addresses to scan...")
        ips = self.generate_common_ips()
        random.shuffle(ips)  # Randomize order
        
        print(f"🚀 Starting scan of {len(ips)} IP addresses...")
        print("💡 Looking for non-whitelisted Minecraft servers...")
        print("-" * 60)
        
        # Split IPs into batches
        batch_size = 20
        ip_batches = [ips[i:i + batch_size] for i in range(0, len(ips), batch_size)]
        
        loop = asyncio.get_event_loop()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            tasks = [
                loop.run_in_executor(executor, self.scan_ip_batch, batch)
                for batch in ip_batches
            ]
            
            completed = 0
            total_batches = len(ip_batches)
            
            for task in asyncio.as_completed(tasks):
                batch_results = await task
                self.found_servers.extend(batch_results)
                completed += 1
                
                if completed % 10 == 0:
                    print(f"📊 Progress: {completed}/{total_batches} batches ({completed/total_batches*100:.1f}%)")
        
        print("-" * 60)
        print(f"🎯 Scan complete! Found {len(self.found_servers)} servers")
        
        if self.found_servers:
            print("\n🏆 WORKING MINECRAFT SERVERS:")
            print("=" * 60)
            for i, server in enumerate(sorted(self.found_servers, key=lambda x: x['ping']), 1):
                players = server.get('players', {})
                online = players.get('online', '?')
                max_players = players.get('max', '?')
                
                desc = server.get('description', {})
                if isinstance(desc, dict):
                    motd = desc.get('text', 'No description')
                else:
                    motd = str(desc)[:50]
                
                print(f"{i:2d}. {server['ip']}:{server['port']}")
                print(f"    Version: {server['version']} | Ping: {server['ping']}ms")
                print(f"    Players: {online}/{max_players} | {motd}")
                print()
        else:
            print("❌ No Minecraft servers found in this scan")

def main():
    scanner = MinecraftScanner()
    
    print("🎮 Advanced Minecraft Server Scanner")
    print("🔎 Searching for public, non-whitelisted servers...")
    print("⚡ Scanning latest versions and popular hosting providers")
    print()
    
    try:
        asyncio.run(scanner.scan_async())
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error during scan: {e}")

if __name__ == "__main__":
    main()
