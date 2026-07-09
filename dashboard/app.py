from flask import Flask, render_template_string
from flask_socketio import SocketIO
import redis
import json
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ahos-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
rd = redis.Redis(host='localhost', port=6379, decode_responses=True)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AHOS — Live Attack Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { text-align: center; font-size: 2em; color: #ff0000; text-shadow: 0 0 20px #ff0000; margin-bottom: 5px; }
        .subtitle { text-align: center; color: #888; margin-bottom: 30px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
        .stat-box { background: #111; border: 1px solid #00ff41; border-radius: 8px; padding: 15px; text-align: center; }
        .stat-box .number { font-size: 2.5em; font-weight: bold; color: #00ff41; }
        .stat-box .label { font-size: 0.8em; color: #888; margin-top: 5px; }
        .stat-box.critical .number { color: #ff0000; }
        .stat-box.high .number { color: #ff6600; }
        .panels { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .panel { background: #111; border: 1px solid #333; border-radius: 8px; padding: 15px; }
        .panel h2 { color: #00ff41; font-size: 1em; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 8px; }
        .event { border-left: 3px solid #00ff41; padding: 8px 12px; margin-bottom: 8px; background: #0d0d0d; border-radius: 4px; font-size: 0.85em; }
        .event.critical { border-left-color: #ff0000; }
        .event.high { border-left-color: #ff6600; }
        .event.medium { border-left-color: #ffcc00; }
        .event .ip { color: #00bfff; font-weight: bold; }
        .event .tool { color: #ff9900; }
        .event .time { color: #555; font-size: 0.75em; float: right; }
        .stix-item { border-left: 3px solid #9900ff; padding: 8px 12px; margin-bottom: 8px; background: #0d0d0d; border-radius: 4px; font-size: 0.82em; }
        .stix-item .mitre { color: #ff00ff; font-weight: bold; }
        #status { text-align: center; padding: 8px; margin-bottom: 20px; border-radius: 4px; font-size: 0.85em; }
        .connected { background: #001a00; color: #00ff41; }
        .disconnected { background: #1a0000; color: #ff0000; }
        @keyframes fadeIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        .event { animation: fadeIn 0.5s ease; }
    </style>
</head>
<body>
    <h1>🍯 AHOS</h1>
    <p class="subtitle">Adaptive Honeypot Orchestration System — Live Dashboard</p>
    <div id="status" class="disconnected">⚡ Connecting...</div>
    <div class="stats">
        <div class="stat-box"><div class="number" id="total">0</div><div class="label">Total Attackers</div></div>
        <div class="stat-box critical"><div class="number" id="critical">0</div><div class="label">Critical Threats</div></div>
        <div class="stat-box high"><div class="number" id="human">0</div><div class="label">Human Attackers</div></div>
        <div class="stat-box"><div class="number" id="stix">0</div><div class="label">STIX Reports</div></div>
    </div>
    <div class="panels">
        <div class="panel"><h2>⚡ Live Attack Feed</h2><div id="feed"></div></div>
        <div class="panel"><h2>📄 STIX Intel Reports</h2><div id="stix-feed"></div></div>
    </div>
    <script>
        const socket = io();
        let total = 0, critical = 0, human = 0, stix = 0;
        socket.on('connect', () => {
            document.getElementById('status').className = 'connected';
            document.getElementById('status').innerText = '✅ Connected to AHOS';
        });
        socket.on('disconnect', () => {
            document.getElementById('status').className = 'disconnected';
            document.getElementById('status').innerText = '❌ Disconnected';
        });
        socket.on('attacker', (data) => {
            total++;
            document.getElementById('total').innerText = total;
            if (data.threat_level === 'critical') { critical++; document.getElementById('critical').innerText = critical; }
            if (data.is_human === 'True' || data.is_human === true) { human++; document.getElementById('human').innerText = human; }
            const feed = document.getElementById('feed');
            const time = new Date().toLocaleTimeString();
            const div = document.createElement('div');
            div.className = `event ${data.threat_level}`;
            div.innerHTML = `<span class="time">${time}</span><span class="ip">${data.src_ip}</span><br><span class="tool">Tool: ${data.detected_tool}</span><span style="color:#ff4444"> | ${data.threat_level.toUpperCase()}</span>`;
            feed.insertBefore(div, feed.firstChild);
            if (feed.children.length > 20) feed.removeChild(feed.lastChild);
        });
        socket.on('stix_report', (data) => {
            stix++;
            document.getElementById('stix').innerText = stix;
            const feed = document.getElementById('stix-feed');
            const div = document.createElement('div');
            div.className = 'stix-item';
            div.innerHTML = `<span class="mitre">${data.mitre_id}</span> — <span style="color:#00bfff">${data.src_ip}</span><br><span style="color:#888">${data.tool}</span>`;
            feed.insertBefore(div, feed.firstChild);
            if (feed.children.length > 20) feed.removeChild(feed.lastChild);
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

def redis_listener():
    pubsub = rd.pubsub()
    pubsub.subscribe("attacker_detected", "stix_reports")
    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        try:
            data = json.loads(message["data"])
            channel = message["channel"]
            if channel == "attacker_detected":
                socketio.emit("attacker", data)
            elif channel == "stix_reports":
                socketio.emit("stix_report", data)
        except Exception as e:
            print(f"[DASHBOARD ERROR] {e}")

def start_dashboard():
    t = threading.Thread(target=redis_listener, daemon=True)
    t.start()
    print("\n[DASHBOARD] Running at http://172.16.170.128:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    start_dashboard()