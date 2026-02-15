from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
import asyncio
import json
from collections import deque, Counter
from datetime import datetime
import sqlite3
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
from scapy.config import conf

conf.use_pcap = True
app = FastAPI(title="Advanced Network Monitor")

CAPTURE_INTERFACE = None
DB_FILE = "network_logs.db"

total_packets = 0
packets_per_second = 0
protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Other": 0}
recent_packets = deque(maxlen=50)
dns_queries = deque(maxlen=20)
port_stats = Counter()
ip_stats = Counter()
alerts = deque(maxlen=10)
traffic_history = deque(maxlen=60)
connected_clients = set()
start_time = None
active_filters = {"protocol": None, "ip": None, "port": None}

PORT_SCAN_THRESHOLD = 10
SUSPICIOUS_PORTS = [21, 22, 23, 3389, 445, 135, 139]

def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            query TEXT,
            response TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            description TEXT,
            src_ip TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def log_to_database(packet_data, table="packets"):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        if table == "packets":
            cursor.execute("""INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (packet_data['timestamp'], packet_data['src_ip'], packet_data['dst_ip'], packet_data['protocol'],
                 packet_data.get('src_port'), packet_data.get('dst_port'), packet_data['length']))
        elif table == "dns_queries":
            cursor.execute("INSERT INTO dns_queries (timestamp, query, response) VALUES (?, ?, ?)",
                (packet_data['timestamp'], packet_data['query'], packet_data.get('response', '')))
        elif table == "alerts":
            cursor.execute("INSERT INTO alerts (timestamp, alert_type, description, src_ip) VALUES (?, ?, ?, ?)",
                (packet_data['timestamp'], packet_data['type'], packet_data['desc'], packet_data['ip']))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")

port_scan_tracker = {}

def detect_port_scan(src_ip, dst_port):
    now = datetime.now()
    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {"ports": set(), "timestamp": now}
    tracker = port_scan_tracker[src_ip]
    if (now - tracker["timestamp"]).seconds > 10:
        tracker["ports"] = set()
        tracker["timestamp"] = now
    tracker["ports"].add(dst_port)
    if len(tracker["ports"]) >= PORT_SCAN_THRESHOLD:
        alert = {
            "time": now.strftime("%H:%M:%S"),
            "type": "Port Scan",
            "description": f"Possible port scan from {src_ip} ({len(tracker['ports'])} ports)",
            "severity": "high"
        }
        alerts.appendleft(alert)
        log_to_database({'timestamp': now.isoformat(), 'type': 'Port Scan', 'desc': alert['description'], 'ip': src_ip}, table="alerts")
        tracker["ports"].clear()

def check_suspicious_port(port, src_ip):
    if port in SUSPICIOUS_PORTS:
        alert = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "Suspicious Port",
            "description": f"Connection to suspicious port {port} from {src_ip}",
            "severity": "medium"
        }
        alerts.appendleft(alert)
        log_to_database({'timestamp': datetime.now().isoformat(), 'type': 'Suspicious Port', 'desc': alert['description'], 'ip': src_ip}, table="alerts")

def apply_filters(packet_info):
    if active_filters["protocol"] and packet_info["protocol"] != active_filters["protocol"]:
        return False
    if active_filters["ip"] and active_filters["ip"] not in [packet_info["src"], packet_info["dst"]]:
        return False
    if active_filters["port"] and active_filters["port"] not in [packet_info.get("src_port"), packet_info.get("dst_port")]:
        return False
    return True

def process_packet(pkt):
    global total_packets, packets_per_second
    if IP in pkt:
        total_packets += 1
        packets_per_second += 1
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "Other"
        src_port = None
        dst_port = None

        if TCP in pkt:
            protocol_stats["TCP"] += 1
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            port_stats[dst_port] += 1
            detect_port_scan(src_ip, dst_port)
            check_suspicious_port(dst_port, src_ip)
        elif UDP in pkt:
            protocol_stats["UDP"] += 1
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            port_stats[dst_port] += 1
        elif ICMP in pkt:
            protocol_stats["ICMP"] += 1
            proto = "ICMP"
        else:
            protocol_stats["Other"] += 1

        if DNS in pkt and pkt.haslayer(DNSQR):
            protocol_stats["DNS"] = protocol_stats.get("DNS", 0) + 1
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            dns_info = {"time": datetime.now().strftime("%H:%M:%S"), "query": query, "src": src_ip}
            dns_queries.appendleft(dns_info)
            log_to_database({'timestamp': datetime.now().isoformat(), 'query': query, 'response': ''}, table="dns_queries")

        ip_stats[src_ip] += 1
        packet_info = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": src_ip,
            "dst": dst_ip,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": len(pkt)
        }
        if apply_filters(packet_info):
            recent_packets.appendleft(packet_info)
        log_to_database({
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'src_port': src_port,
            'dst_port': dst_port,
            'length': len(pkt)
        })

async def broadcaster():
    global packets_per_second, start_time
    while True:
        await asyncio.sleep(1)
        if not connected_clients:
            packets_per_second = 0
            continue
        traffic_history.append(packets_per_second)
        uptime = str(datetime.now() - start_time).split('.')[0] if start_time else "00:00:00"
        top_ports = [{"port": port, "count": count} for port, count in port_stats.most_common(5)]
        top_ips = [{"ip": ip, "count": count} for ip, count in ip_stats.most_common(5)]
        data = {
            "total_packets": total_packets,
            "packets_per_second": packets_per_second,
            "recent_packets": list(recent_packets),
            "protocol_stats": protocol_stats,
            "dns_queries": list(dns_queries),
            "top_ports": top_ports,
            "top_ips": top_ips,
            "alerts": list(alerts),
            "traffic_history": list(traffic_history),
            "uptime": uptime,
            "active_filters": active_filters
        }
        packets_per_second = 0
        disconnected = set()
        for client in connected_clients:
            try:
                await client.send_text(json.dumps(data))
            except:
                disconnected.add(client)
        for client in disconnected:
            connected_clients.discard(client)

@app.on_event("startup")
async def startup():
    global start_time
    start_time = datetime.now()
    print("=" * 50)
    print("🚀 Advanced Network Monitor Starting...")
    print("=" * 50)
    init_database()
    print(f"📡 Interface: {CAPTURE_INTERFACE or 'Auto-detect'}")
    print(f"💾 Database: {DB_FILE}")
    try:
        sniffer = AsyncSniffer(iface=CAPTURE_INTERFACE, prn=process_packet, store=False)
        sniffer.start()
        asyncio.create_task(broadcaster())
        print("✅ Packet sniffer started successfully!")
        print("🔒 Security monitoring enabled")
        print("=" * 50)
    except Exception as e:
        print(f"❌ Sniffer Error: {e}")
        print("💡 Tip: Run as Administrator")

@app.get("/")
async def index():
    return FileResponse("index.html")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    print(f"✅ Client connected. Total: {len(connected_clients)}")
    try:
        while True:
            message = await websocket.receive_text()
            if message.startswith("filter:"):
                filter_data = json.loads(message.split(":", 1)[1])
                active_filters.update(filter_data)
                print(f"🔍 Filters updated: {active_filters}")
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        print(f"❌ Client disconnected. Total: {len(connected_clients)}")
