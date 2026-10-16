from flask import Flask, jsonify, request
from flask_cors import CORS
from plc import SimulatedPLC
import threading
import time


app = Flask(__name__)

# Allow Windows HMI to connect
CORS(app)


# ==========================================
# CREATE PLC
# ==========================================

plc = SimulatedPLC()


# ==========================================
# PLC PROCESS
# ==========================================

def plc_process():

    plc.start_motor()

    while True:

        plc.update_process()

        time.sleep(1)


# ==========================================
# PLC DATA API
# ==========================================

@app.route("/plc/data")
def get_plc_data():

    return jsonify(plc.get_data())


# ==========================================
# SIMULATED UNAUTHORIZED PLC MANIPULATION
# ==========================================

@app.route("/plc/modify", methods=["POST"])
def modify_plc():

    data = request.get_json()

    rpm = data.get("rpm")

    if rpm is None:
        return jsonify({"error": "RPM is required"}), 400

    plc.speed = int(rpm)

    return jsonify({
        "message": "PLC parameter modified",
        "authorization": "UNAUTHORIZED",
        "rpm": plc.speed
    })


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    thread = threading.Thread(target=plc_process)

    thread.daemon = True

    thread.start()

    print("====================================")
    print("       PLC API STARTED")
    print("====================================")
    print("API: http://0.0.0.0:5000")

    app.run(
        host="0.0.0.0",
        port=5000
    )
