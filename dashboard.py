from flask import Flask, render_template
from flask_socketio import SocketIO
import json
import time
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

def watch_logs():
    with open("alerts.log", "r") as f:
        # Start at the end of the file so we don't spam old alerts on load
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Small delay to save CPU
                continue
            try:
                alert = json.loads(line)
                socketio.emit('new_alert', alert)
            except Exception as e:
                print(f"Error parsing log: {e}")

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    # The 'daemon=True' ensures the thread dies when the main app stops
    threading.Thread(target=watch_logs, daemon=True).start()
    socketio.run(app, debug=True, port=5000)