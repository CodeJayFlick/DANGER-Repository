Here is the translation of the Java code into Python:

```Python
import asyncio
from ftcrobot import Gamepad, ElapsedTime, LinearOpMode

class ConceptGamepadRumble(LinearOpMode):
    def __init__(self):
        super().__init__()
        self.last_a = False  # Use to track the prior button state.
        self.last_lb = False  # Use to track the prior button state.
        self.high_level = False  # used to prevent multiple level-based rumbles.
        self.second_half = False  # Use to prevent multiple half- time warning rumbles.

    async def runOpMode(self):
        custom_rumble_effect = Gamepad.RumbleEffect()
        for i in range(3):  # Create a three-pulse rumble sequence: right, left, left
            if i == 0:
                custom_rumble_effect.add_step(1.0, 500)  # Rumble right motor 100% for 500 mSec
            elif i == 2:
                custom_rumble_effect.add_step(1.0, 250)  # Rumble left motor 100% for 250 mSec
        await self.gamepad.run_custom_rumble(custom_rumble_effect)

        telemetry = self.telemetry
        telemetry.add_data(">", "Press Start")
        telemetry.update()
        await asyncio.sleep(2)
        runtime = ElapsedTime()

        while not is_op_mode_active():
            current_a = self.gamepad.a  # Read and save the current gamepad button states.
            current_lb = self.gamepad.left_bumper

            if (runtime.seconds() > HALF_TIME) and not self.second_half:  # Watch the runtime timer, and run the custom rumble when we hit half-time. Make sure we only signal once by setting "secondHalf" flag to prevent further rumbles.
                await self.gamepad.run_custom_rumble(custom_rumble_effect)
                self.second_half = True

            if not self.second_half:  # Display the time remaining while we are still counting down.
                telemetry.add_data(">", f"Halftime Alert Countdown: {HALF_TIME - runtime.seconds():.0f} Sec")
            else:
                await asyncio.sleep(1)

            if current_lb:  # If Left Bumper is being pressed, power the rumble motors based on the two trigger depressions.
                self.gamepad.rumble(self.gamepad.left_trigger, self.gamepad.right_trigger)
                telemetry.add_data(">", "Squeeze triggers to control rumbles")
                telemetry.add_data("> : Rumble", f"Left: {self.game pad.left_trigger * 100:.0f}%   Right: {self.gamepad.right_trigger * 100:.0f}%" )
            else:
                if self.last_lb:  # Make sure rumble is turned off when Left Bumper is released (only one time each press)
                    await self.gamepad.stop_rumble()
                telemetry.add_data(">", "Hold Left-Button to test Manual Rumble")
                telemetry.add_data(">", "Press A (Cross) for three blips")

            last_lb = current_lb  # remember the current button state for next time around the loop

            if current_a and not self.last_a:  # Blip 3 times at the moment that A (Cross) is pressed. BUT!!! Skip it altogether if the Gamepad is already rumbling.
                await self.gamepad.rumble_blips(3)
            last_a = current_a  # remember the current button state for next time around the loop

            if gamepad.right_trigger > TRIGGER_THRESHOLD:  # Rumble once when gamepad right trigger goes above the THRESHOLD.
                if not high_level:
                    await self.gamepad.rumble(0.9, 0)
                    high_level = True
                else:
                    high_level = False

            telemetry.update()
            await asyncio.sleep(10)

    def is_op_mode_active(self):
        return super().is_op_mode_active()

if __name__ == "__main__":
    opmode = ConceptGamepadRumble()
    opmode.run_op_mode()
```

Please note that Python does not support the same kind of event-driven programming as Java, so I had to make some changes.