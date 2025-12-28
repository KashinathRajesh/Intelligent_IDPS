import subprocess
import time
import sys
import os

def start_project():
    print("--- IDPS Interview Presentation Launcher ---")
    
    try:
        # 1. Start the Flask Dashboard
        print("[*] Launching SOC Dashboard (Backend & Frontend)...")
        dashboard_proc = subprocess.Popen(
            [sys.executable, "dashboard.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Give the dashboard a moment to bind to port 5000
        time.sleep(3)
        print("[+] Dashboard live at http://127.0.0.1:5000")

        # 2. Start the IDPS Engine (main.py)
        # Note: This requires Administrator privileges on Windows
        print("[*] Launching IDPS Sniffer Engine...")
        sniffer_proc = subprocess.Popen(
            [sys.executable, "main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        print("\n[!] BOTH SYSTEMS ACTIVE. Press Ctrl+C to stop all processes.\n")

        # Monitor output from both (optional)
        while True:
            # Check if processes are still running
            if dashboard_proc.poll() is not None:
                print("[!] Dashboard process stopped unexpectedly.")
                break
            if sniffer_proc.poll() is not None:
                print("[!] Sniffer process stopped unexpectedly.")
                break
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Shutting down IDPS and Dashboard...")
        dashboard_proc.terminate()
        sniffer_proc.terminate()
        print("[+] All systems offline.")
    except Exception as e:
        print(f"[!] Launcher Error: {e}")

if __name__ == "__main__":
    start_project()