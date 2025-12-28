import time
import mysql.connector
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import threading
import yaml

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

def get_db_connection():
    return mysql.connector.connect(
        host=config['mysql']['host'],
        user=config['mysql']['user'],
        password=config['mysql']['password'],
        database=config['mysql']['database']
    )

def format_alert(alert):
    """Aligns DB column names with Frontend expectations."""
    alert['timestamp'] = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
    # FIX: Map 'alert_type' from MySQL to 'type' for the Dashboard
    alert['type'] = alert.pop('alert_type') 
    return alert

@socketio.on('connect')
def handle_connect():
    """Sends the last 50 alerts to the user upon connecting."""
    print("[+] Client connected. Sending historical data...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
        history = cursor.fetchall()
        conn.close()
        
        for alert in reversed(history):
            emit('new_alert', format_alert(alert))
    except Exception as e:
        print(f"[!] History Load Error: {e}")

def fetch_new_alerts():
    """Polls for new alerts and broadcasts them live."""
    last_id = 0
    # Initialize last_id to current max
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(id) FROM alerts")
    res = cursor.fetchone()[0]
    last_id = res if res else 0
    conn.close()

    while True:
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM alerts WHERE id > %s ORDER BY id ASC", (last_id,))
            new_alerts = cursor.fetchall()

            for alert in new_alerts:
                socketio.emit('new_alert', format_alert(alert))
                last_id = alert['id']

            conn.close()
        except Exception as e:
            print(f"[!] DB Polling Error: {e}")
        time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    threading.Thread(target=fetch_new_alerts, daemon=True).start()
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)