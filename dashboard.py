from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import json
import time
import threading
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersecurity_is_cool'
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "alerts.log"

def get_last_n_alerts(n=50):
    alerts = []
    if not os.path.exists(LOG_FILE):
        return alerts
    
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        last_lines = lines[-n:]
        for line in last_lines:
            try:
                alerts.append(json.loads(line))
            except:
                continue
    return alerts

def watch_logs():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                alert = json.loads(line)
                socketio.emit('new_alert', alert)
            except:
                pass

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    history = get_last_n_alerts(50)
    for alert in history:
        emit('new_alert', alert, room=request.sid)

if __name__ == "__main__":
    socketio.start_background_task(watch_logs)
    socketio.run(app, debug=True, port=5000)