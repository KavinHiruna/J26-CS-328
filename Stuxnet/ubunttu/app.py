from flask import Flask, jsonify
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
# PLC API
# ==========================================

@app.route("/plc/data")
def get_plc_data():

    return jsonify(plc.get_data())


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
    print("API: http://0.0.0.0:5000/plc/data")

    app.run(
        host="0.0.0.0",
        port=5000
    )
