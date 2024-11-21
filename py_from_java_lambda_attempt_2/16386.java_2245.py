Here is the translation of the Java code to Python:
```
import asyncio
from pyb import OpticalDistanceSensor  # assuming you have a PyB library with this class

class SensorMROpticalDistance:
    def __init__(self):
        self.odssensor = None  # Hardware Device Object

    async def run_opmode(self):
        await asyncio.sleep(0)  # wait for the start button to be pressed
        while True:  # loop and read the light levels
            if not op_mode_active():  # Note we use opModeIsActive() as our loop condition because it is an interruptible method.
                break

            raw_light = self.odssensor.get_raw_light_detected()
            normal_light = self.odssensor.get_light_detected()

            await telemetry.add_data("Raw", raw_light)
            await telemetry.add_data("Normal", normal_light)

            await telemetry.update()

    def op_mode_active(self):
        # implement your logic to check if the op mode is active
        pass

# usage:
odssensor = OpticalDistanceSensor()
sensor_mroptical_distance = SensorMROpticalDistance(odssensor)
asyncio.run(sensor_mroptical_distance.run_opmode())
```
Note that I had to make some assumptions about the Python libraries and classes you might be using. Specifically, I assumed:

* You have a `PyB` library with an `OpticalDistanceSensor` class.
* You are using the `asyncio` library for asynchronous programming.
* You have a `telemetry` object that has methods like `add_data()` and `update()`.
* The `op_mode_active()` method is not implemented, as it depends on your specific use case.

Please adjust this code to fit your actual Python setup.