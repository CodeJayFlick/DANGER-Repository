import asyncio
from pyb import ColorSensor, LED, Gamepad1

class SensorMRColor:
    def __init__(self):
        self.color_sensor = ColorSensor('sensor_color')
        self.b_led_on = True
        self.relative_layout_id = 'RelativeLayout'
        self.values = [0.0, 0.0, 0.0]

    async def run_op_mode(self):
        while not gamepad1.x:
            await asyncio.sleep(0)
        
        try:
            while True:
                if gamepad1.x and (gamepad1.x != self.b_prev_state):
                    self.b_led_on = not self.b_led_on
                    self.color_sensor.enable_led(self.b_led_on)

                self.values[2] = self.color_sensor.blue() * 8.0
                self.values[1] = self.color_sensor.green() * 8.0
                self.values[0] = self.color_sensor.red() * 8.0

                print(f"LED: {'On' if self.b_led_on else 'Off'}")
                print(f"CLEAR: {self.color_sensor.alpha()}")
                print(f"RED   : {self.color_sensor.red()}")
                print(f"GREEN : {self.color_sensor.green()}")
                print(f"BLUE  : {self.color_sensor.blue()}")

        finally:
            self.relative_layout.post(lambda: self.relative_layout.set_background_color(Color.HSVToColor(0xff, self.values)))
