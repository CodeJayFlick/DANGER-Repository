Here's your Java code translated into Python:

```Python
import threading
from java.io import File
from com.qualcomm.ftccommon.SoundPlayer import SoundPlayer
from org.firstinspires.legacy.opmode.LinearOpMode import LinearOpMode
from org.firstinspires.legacy.opmode.TeleOp import TeleOp

class ConceptSoundsOnBotJava(LinearOpMode):
    def __init__(self):
        super().__init__()
        self.sound_path = "/FIRST/blocks/sounds"
        self.gold_file = File("/sdcard" + self.sound_path + "/gold.wav")
        self.silver_file = File("/sdcard" + self.sound_path + "/silver.wav")

    @TeleOp(name="Concept: Sound Files", group="Concept")
    def runOpMode(self):
        # Make sure that the sound files exist on the phone
        gold_found = self.gold_file.exists()
        silver_found = self.silver_file.exists()

        # Display sound status
        telemetry.addData("gold sound", "Found" if gold_found else f"Not Found. Copy gold.wav to {self.sound_path}")
        telemetry.update()
        telemetry.addData("silver sound", "Found" if silver_found else f"Not Found. Copy silver.wav to {self.sound_path}")
        telemetry.update()

        # Wait for the game to start (driver presses PLAY)
        while not isStarted():
            pass

        # run until the end of the match (driver presses STOP)
        while self.opModeIsActive():
            if gold_found and gamepad1.x:
                SoundPlayer.getInstance().startPlaying(self.hardwareMap.appContext, self.gold_file)
                telemetry.addData("Playing", "Gold File")
                telemetry.update()
            elif silver_found and gamepad1.b:
                SoundPlayer.getInstance().startPlaying(self.hardwareMap.appContext, self.silver_file)
                telemetry.addData("Playing", "Silver File")
                telemetry.update()

        # Save last button states
```

Please note that this code is not a direct translation from Java to Python. It's an attempt at translating the logic and functionality of your original code into Python.