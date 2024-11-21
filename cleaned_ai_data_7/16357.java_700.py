import time
from ftcrobotlib import Telemetry, ElapsedTime, LinearOpMode, Gamepad1

class ConceptTelemetry(LinearOpMode):
    poem = [
        "Mary had a little lamb,", 
        "His fleece was white as snow,", 
        "And everywhere that Mary went,", 
        "The lamb was sure to go.", 
        "", 
        "He followed her to school one day,", 
        "Which was against the rule,", 
        "It made the children laugh and play", 
        "To see a lamb at school.", 
        "", 
        "And so the teacher turned it out,", 
        "But still it lingered near,", 
        "And waited patiently about,", 
        "Till Mary did appear.", 
        "", 
        "\"Why does the lamb love Mary so?\"", 
        "The eager children cry.", 
        "\"Why, Mary loves the lamb, you know,\"", 
        "The teacher did reply.", 
        ""
    ]

    def __init__(self):
        super().__init__()
        self.poem_line = 0
        self.poem_elapsed = ElapsedTime()
        self.opmode_run_time = ElapsedTime()

    @Override
    public void runOpMode() {
        while not isStarted():
            telemetry.addData("time", "%.1f seconds" % opmode_run_time.seconds())
            telemetry.update()
            idle()

        # Ok, we've been given the ok to go

        # As an illustration, the first line on our telemetry display will display the battery voltage.
        # The idea here is that it's expensive to compute the voltage (at least for purposes of illustration) 
        # so you don't want to do it unless the data is actually going to make it to the driver station
        # Note that getBatteryVoltage() below returns 'Infinity' if there's no voltage sensor attached.
        telemetry.addData("voltage", "%.1f volts" % self.get_battery_voltage())

        opmode_run_time.reset()
        loop_count = 0

        while isOpModeActive():
            if poem_elapsed.seconds() > s_poem_interval:
                self.emit_poem_line()

            # As an illustration, show some loop timing information
            telemetry.addData("loop count", loop_count)
            telemetry.addData("ms/loop", "%.3f ms" % opmode_run_time.milliseconds() / loop_count)

            # Show joystick information as some other illustrative data
            telemetry.addLine("left joystick | ")
            telemetry.addData("x", gamepad1.left_stick_x)
            telemetry.addData("y", gamepad1.left_stick_y)
            telemetry.addLine("right joystick | ")
            telemetry.addData("x", gamepad1.right_stick_x)
            telemetry.addData("y", gamepad1.right_stick_y)

            # Transmit the telemetry to the driver station, subject to throttling.
            telemetry.update()

            loop_count += 1
    }

    def emit_poem_line(self):
        telemetry.log().add(poem[self.poem_line])
        self.poem_line = (self.poem_line + 1) % len(self.poem)
        self.poem_elapsed.reset()

    def get_battery_voltage(self):
        result = float('inf')
        for sensor in hardware_map.voltage_sensor:
            voltage = sensor.get_volt()
            if voltage > 0:
                result = min(result, voltage)

        return result
