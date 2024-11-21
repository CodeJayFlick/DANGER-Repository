Here is the translation of the given Java code into Python:

```Python
import time
from math import clip

class BasicOpMode_Iterative:
    def __init__(self):
        self.runtime = time.time()
        self.left_drive = None
        self.right_drive = None

    # Code to run ONCE when the driver hits INIT
    def init(self, telemetry):
        telemetry.addData("Status", "Initialized")

        # Initialize the hardware variables.
        self.left_drive = self.hardware_map.get('left_ drive')
        self.right_drive = self.hardware_map.get('right_ drive')

        # Most robots need the motor on one side to be reversed to drive forward
        # Reverse the motor that runs backwards when connected directly to the battery
        self.left_drive.set_direction(1)
        self.right_drive.set_direction(-1)

        telemetry.addData("Status", "Initialized")

    # Code to run REPEATEDLY after the driver hits INIT, but before they hit PLAY
    def init_loop(self):
        pass

    # Code to run ONCE when the driver hits PLAY
    def start(self):
        self.runtime = time.time()

    # Code to run REPEATEDLY after the driver hits PLAY but before they hit STOP
    def loop(self, gamepad1, telemetry):
        left_power = 0.0
        right_power = 0.0

        drive = -gamepad1.left_stick_y
        turn = gamepad1.right_stick_x
        left_power = clip(drive + turn, -1.0, 1.0)
        right_power = clip(drive - turn, -1.0, 1.0)

        self.left_drive.set_power(left_power)
        self.right_drive.set_power(right_power)

        telemetry.addData("Status", "Run Time: " + str(time.time() - self.runtime))
        telemetry.addData("Motors", "left (%.2f), right (%.2f)" % (left_power, right_power))

    # Code to run ONCE after the driver hits STOP
    def stop(self):
        pass

# Usage:
op_mode = BasicOpMode_Iterative()
while True:
    op_mode.init(telemetry)
    while not gamepad1.a and not gamepad1.b:  # Wait for INIT button press
        time.sleep(0.01)

    while gamepad1.a or gamepad1.b:  # Loop until PLAY/STOP buttons are pressed
        if gamepad1.a:
            op_mode.start()
        elif gamepad1.b:
            op_mode.stop()

        op_mode.loop(gamepad1, telemetry)
```

Please note that this is a direct translation of the given Java code into Python. It may not be exactly what you would write in Python as it's still following the structure and naming conventions from the original Java code.