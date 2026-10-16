class SimulatedPLC:

    def __init__(self):

        # ==============================
        # PLC VARIABLES
        # ==============================

        self.motor_status = False
        self.speed = 0
        self.temperature = 25.0
        self.pressure = 1.0
        self.vibration = 0.0

        # ==============================
        # SECURITY / CONFIGURATION
        # ==============================

        self.authorization = "AUTHORIZED"
        self.configuration_status = "NORMAL"

    def start_motor(self):

        self.motor_status = True

    def stop_motor(self):

        self.motor_status = False
        self.speed = 0

    def update_process(self):

        if self.motor_status:

            # Increase centrifuge speed
            if self.speed < 1000:
                self.speed += 50

            # Simulated sensor values
            self.temperature = 25 + (self.speed / 100)

            self.pressure = 1.0 + (self.speed / 1000)

            self.vibration = self.speed / 500

        else:

            self.speed = 0
            self.temperature = 25.0
            self.pressure = 1.0
            self.vibration = 0.0

    def get_data(self):

        # ==============================
        # PROCESS STATUS
        # ==============================

        if (
            self.speed <= 1000
            and self.temperature <= 35
            and self.pressure <= 2
            and self.vibration <= 2
        ):

            status = "NORMAL"

        else:

            status = "WARNING"


        # ==============================
        # PLC DATA
        # ==============================

        return {

            "motor_status": self.motor_status,

            # Dashboard calls this RPM
            "rpm": self.speed,

            "temperature": round(self.temperature, 2),

            "pressure": round(self.pressure, 2),

            "vibration": round(self.vibration, 2),

            # PLC status
            "plc_status": status,

            # Security status
            "authorization": self.authorization,

            # Configuration status
            "configuration_status": self.configuration_status
        }


# ==========================================
# TEST PLC DIRECTLY
# ==========================================

if __name__ == "__main__":

    import time

    plc = SimulatedPLC()

    plc.start_motor()

    print("PLC started")
    print("Motor started")

    while True:

        plc.update_process()

        data = plc.get_data()

        print(
            f"Status: {data['plc_status']} | "
            f"Speed: {data['rpm']} RPM | "
            f"Temperature: {data['temperature']} C | "
            f"Pressure: {data['pressure']} bar | "
            f"Vibration: {data['vibration']} mm/s | "
            f"Authorization: {data['authorization']}"
        )

        time.sleep(1)
