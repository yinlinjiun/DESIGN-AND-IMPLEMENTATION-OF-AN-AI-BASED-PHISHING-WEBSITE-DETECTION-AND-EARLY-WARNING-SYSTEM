import os
import sys
import subprocess
import time
import webbrowser
import socket

os.chdir(os.path.dirname(os.path.abspath(__file__)))


def wait_for_server(host="127.0.0.1", port=5000, timeout=10):
    # 轮询本地端口，确认Flask服务真正启动后再打开浏览器。
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


print("[Starting] Flask app is launching...")
# 使用当前Python解释器启动app.py，避免系统中多个Python版本造成启动不一致。
proc = subprocess.Popen([sys.executable, "app.py"])

if wait_for_server():
    print("[Done] Browser opened: http://127.0.0.1:5000")
    webbrowser.open("http://127.0.0.1:5000")
else:
    print("[Timeout] Please visit http://127.0.0.1:5000 manually")

try:
    proc.wait()
except KeyboardInterrupt:
    proc.terminate()
