import asyncio
from modernrobotics import ModernRoboticsI2cRangeSensor
from robotpy import LinearOpMode, Disabled, TeleOp
from distanceunit import DistanceUnit

class SensorMRRangeSensor(LinearOpMode):
    def __init__(self):
        super().__init__()
        self.range_sensor = None

    async def run_opmode(self):
        # get a reference to our compass
        self.range_sensor = await self.hardware_map.get(ModernRoboticsI2cRangeSensor, "sensor_range")

        # wait for the start button to be pressed
        await self.wait_for_start()

        while self.op_mode_is_active():
            telemetry.add_data("raw ultrasonic", self.range_sensor.raw_ultrasonic())
            telemetry.add_data("raw optical", self.range_sensor.raw_optical())
            telemetry.add_data("cm optical", f"{self.range_sensor.cm_optical():.2f} cm")
            telemetry.add_data("cm", f"{self.range_sensor.get_distance(DistanceUnit.CM):.2f} cm")
            await telemetry.update()

    async def op_mode_is_active(self):
        return self.is_op_mode_active()
