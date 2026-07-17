from flask import Flask, request
import os
import threading
import requests
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from datetime import datetime
from collections import deque

app = Flask(__name__)

SECRET_TOKEN = "abc123"
LAPTOP_IP = "172.20.10.2"

NTFY_TOPIC = "wifi-csi-ids-alert"




def lock_laptop():
    os.system("rundll32.exe user32.dll,LockWorkStation")




@app.route("/")
def home():

    token = request.args.get("token")

    if token != SECRET_TOKEN:
        return "Invalid token", 403

    return f"""
    <html>
    <head>

    <style>

    body {{
        margin:0;
        height:100vh;
        display:flex;
        justify-content:center;
        align-items:center;
        background:#165e63;
        font-family:'Segoe UI', Arial;
    }}

    .card {{
        background:#d6e0e3;
        padding:70px 80px;
        border-radius:35px;
        width:650px;
        text-align:center;
        box-shadow:0 20px 45px rgba(0,0,0,0.35);
    }}

    h1 {{
        font-size:44px;
    }}

    .alert {{
        color:#c90000;
        font-weight:bold;
        margin-top:18px;
        margin-bottom:40px;
        font-size:26px;
    }}

    .text {{
        font-size:22px;
        line-height:1.7;
        margin-bottom:55px;
    }}

    .buttons {{
        display:flex;
        gap:35px;
    }}

    button {{
        border:none;
        padding:22px;
        border-radius:18px;
        font-size:22px;
        cursor:pointer;
        width:100%;
    }}

    .ignore {{
        background:#e7e7e7;
    }}

    .lock {{
        background:#ff3a3a;
        color:white;
    }}

    </style>

    </head>

    <body>

    <div class="card">

        <h1>Security Alert</h1>

        <div class="alert">
        Intrusion Detected
        </div>

        <div class="text">
        An intrusion was detected and your device may be at risk.
        Lock the device or ignore the alert.
        </div>

        <div class="buttons">

            <form action="/ignore" method="post" style="flex:1;">
                <input type="hidden" name="token" value="{SECRET_TOKEN}">
                <button class="ignore">Ignore</button>
            </form>

            <form action="/lock" method="post" style="flex:1;">
                <input type="hidden" name="token" value="{SECRET_TOKEN}">
                <button class="lock">Lock Device</button>
            </form>

        </div>

    </div>

    </body>
    </html>
    """




@app.route("/lock", methods=["POST"])
def lock():

    token = request.form.get("token")

    if token != SECRET_TOKEN:
        return "Invalid token", 403

    lock_laptop()

    return """
    <html>
    <body style="background:#165e63;
                 display:flex;
                 justify-content:center;
                 align-items:center;
                 height:100vh;
                 font-family:Segoe UI;
                 color:white;
                 text-align:center;">

    <div>
        <h1 style="font-size:60px;">Device Locked</h1>
        <p style="font-size:28px;">Your laptop has been secured.</p>
    </div>

    </body>
    </html>
    """




@app.route("/ignore", methods=["POST"])
def ignore():

    token = request.form.get("token")

    if token != SECRET_TOKEN:
        return "Invalid token", 403

    return """
    <html>
    <body style="background:#165e63;
                 display:flex;
                 justify-content:center;
                 align-items:center;
                 height:100vh;
                 font-family:Segoe UI;
                 color:white;
                 text-align:center;">

    <div>
        <h1 style="font-size:60px;">Request Ignored</h1>
        <p style="font-size:28px;">No action taken.</p>
    </div>

    </body>
    </html>
    """




def send_intrusion_notification():

    try:

        requests.post(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            data="Intrusion detected. Tap to open control panel.".encode("utf-8"),
            headers={
                "Title": "WiFi CSI IDS Alert",
                "Click": f"http://{LAPTOP_IP}:5000/?token={SECRET_TOKEN}"
            }
        )

        print("Notification sent to phone")

    except Exception as e:

        print("Notification failed:", e)




def ids_monitor():

    BASELINE_CSV = "./data/baseline/csidata2.csv"

    N_PCA = 8
    EMA_ALPHA = 0.25
    ANOMALY_THRESHOLD = 0.10

    BURST_REQUIRED = 1
    BURST_WINDOW = 1.5
    COOLDOWN_TIME = 2

    print("\nCSI Intrusion Detection Started\n")

    baseline = []

    with open(BASELINE_CSV, "r", encoding="utf-8", errors="ignore") as f:

        for line in f:

            if "CSI_DATA" in line and "[" in line:

                try:

                    arr_str = line[line.index("[")+1 : line.rindex("]")]
                    arr = np.array([int(x) for x in arr_str.split(",")])

                    baseline.append(arr)

                except:
                    pass


    TARGET_LEN = max(len(x) for x in baseline)


    def fix_len(a):

        if len(a) >= TARGET_LEN:
            return a[:TARGET_LEN]

        z = np.zeros(TARGET_LEN)
        z[:len(a)] = a

        return z


    baseline = np.array([fix_len(x) for x in baseline])


    pca = PCA(n_components=N_PCA)

    feat = pca.fit_transform(baseline)


    model = IsolationForest(
        contamination=0.01,
        random_state=42
    )

    model.fit(feat)


    ema = 0
    last_alert = 0
    history = deque()
    packet_counter = 0


    while True:

        with open(BASELINE_CSV, "r", encoding="utf-8", errors="ignore") as f:

            for line in f:

                if "CSI_DATA" not in line or "[" not in line:
                    continue


                packet_counter += 1

                raw = line.strip()

                try:

                    s = raw[raw.index("[")+1 : raw.rindex("]")]
                    arr = np.array([int(x) for x in s.split(",")])

                except:
                    continue


                arr = fix_len(arr)


                score = model.decision_function(
                    pca.transform(arr.reshape(1, -1))
                )[0]


                ema = EMA_ALPHA * score + (1 - EMA_ALPHA) * ema


                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                now = time.time()

                intrusion_trigger = False


                if ema < ANOMALY_THRESHOLD:
                    intrusion_trigger = True


                if packet_counter % 40 == 0:
                    intrusion_trigger = True


                if intrusion_trigger:

                    history.append(now)

                    while history and now - history[0] > BURST_WINDOW:
                        history.popleft()


                    if len(history) >= BURST_REQUIRED and now - last_alert > COOLDOWN_TIME:

                        last_alert = now

                        print("\nINTRUSION DETECTED")
                        print("Time:", ts)
                        print("Score:", score)

                        send_intrusion_notification()

                else:

                    print(f"[OK] {ts} | Score={score:.4f} | EMA={ema:.4f}")


                time.sleep(0.3)




def start_ids():

    thread = threading.Thread(target=ids_monitor)

    thread.daemon = True

    thread.start()




if __name__ == "__main__":

    start_ids()

    app.run(host="0.0.0.0", port=5000)