Here is the translation of the given Java code into Python:

```Python
import time
from typing import Dict

class BasicOpMode_Linear:
    def __init__(self):
        self.runtime = time.time()
        self.left_drive = None
        self.right_drive = None

    @property
    def telemetry(self) -> Dict[str, str]:
        return {"Status": "Initialized"}

    def run_op_mode(self):
        while not is_stop():
            left_power = -gamepad1.left_stick_y + gamepad1.right_stick_x
            right_power = -gamepad1.left_stick_y - gamepad1.right_stick_x

            self.left_drive.set_power(left_power)
            self.right_drive.set_power(right_power)

            self.telemetry["Status"] = f"Run Time: {time.time()}"
            self.telemetry["Motors"] = f"left ({left_power:.2f}), right ({right_power:.2f})"
            print(self.telemetry)
            time.sleep(0.01)  # Update the telemetry every 10 milliseconds

    def is_stop(self):
        return False
```

Note that this Python code does not include any equivalent of Java's `@TeleOp` and `@Disabled`, as these are annotations specific to Android Studio, which do not have a direct translation in Python.