Here is the translation of the Java code into Python:

```Python
import telemetry
from hardware import Pushbot
from gyro import ModernRoboticsI2cGyro

class PushbotAutoDriveByGyro:
    def __init__(self):
        self.robot = Pushbot()
        self.gyro = None

    @Autonomous(name="Pushbot: Auto Drive By Gyro", group="Pushbot")
    @Disabled
    def runOpMode(self):

        # Initialize the standard drive system variables.
        self.robot.init(hardwareMap)
        self.gyro = hardwareMap.gyroSensor.get("gyro")

        # Ensure the robot is stationary, then reset the encoders and calibrate the gyro.
        self.robot.leftDrive.setMode(DcMotor.RunMode.STOP_AND_RESET_ENCODER)
        self.robot.rightDrive.setMode(DcMotor.RunMode.STOP_AND_RESET_ENCODER)

        # Send telemetry message to alert driver that we are calibrating;
        telemetry.addData(">", "Calibrating Gyro")
        telemetry.update()

        self.gyro.calibrate()

        # Make sure the gyro is calibrated before continuing.
        while not isStopRequested() and self.gyro.isCalibrating():
            sleep(50)
            idle()

        telemetry.addData(">", "Robot Ready.")
        telemetry.update()

        self.robot.leftDrive.setMode(DcMotor.RunMode.RUN_USING_ENCODER)
        self.robot.rightDrive.setMode(DcMotor.RunMode.RUN_USING_ENCODER)

        # Wait for the game to start (Display Gyro value), and reset gyro before we move..
        while not isStarted():
            telemetry.addData(">", "Robot Heading = %d", self.gyro.getIntegratedZValue())
            telemetry.update()

        self.gyro.resetZAxisIntegrator()

        # Step through each leg of the path,
        # Note: Reverse movement is obtained by setting a negative distance (not speed)
        gyroDrive(DRIVE_SPEED, 48.0, 0.0)     # Drive FWD 48 inches
        gyroTurn(TURN_ SPEED, -45.0)          # Turn CCW to -45 Degrees
        gyroHold(TURN_ SPEED, -45.0, 0.5)     # Hold -45 Deg heading for a 1/2 second
        gyroDrive(DRIVE_SPEED, 12.0, -45.0)   # Drive FWD 12 inches at 45 degrees
        gyroTurn(TURN_ SPEED, 45.0)          # Turn CW to 45 Degrees
        gyroHold(TURN_ SPEED, 45.0, 0.5)     # Hold 45 Deg heading for a 1/2 second
        gyroTurn(TURN_ SPEED, 0.0)          # Turn CW to 0 Degrees
        gyroHold(TURN_ SPEED, 0.0, 1.0)     # Hold 0 Deg heading for a 1 second
        gyroDrive(DRIVE_SPEED,-48.0, 0.0)    # Drive REV 48 inches

        telemetry.addData("Path", "Complete")
        telemetry.update()

    def gyroDrive(self, speed, distance, angle):
        newLeftTarget = self.robot.leftDrive.getCurrentPosition() + int(distance * COUNTS_PER_INCH)
        newRightTarget = self.robot.rightDrive.getCurrentPosition() + int(distance * COUNTS_PER_INCH)

        if opModeIsActive():
            # Determine new target position and pass to motor controller
            robot. leftDrive.setTargetPosition(newLeftTarget)
            robot.rightDrive.setTargetPosition(newRightTarget)

            robot.leftDrive.setMode(DcMotor.RunMode.RUN_TO_POSITION)
            robot.rightDrive.setMode(DcMotor.RunMode.RUN_TO_POSITION)

            # Start motion.
            speed = Range.clip(abs(speed), 0.0, 1.0)
            robot.leftDrive.setPower(speed)
            robot.rightDrive.setPower(speed)

            while opModeIsActive() and (robot.leftDrive.isBusy() or robot.rightDrive.isBusy()):
                error = getError(angle)
                steer = getSteer(error, P_DRIVE_COEFF)

                if distance < 0:
                    steer *= -1.0

                leftSpeed = speed - steer
                rightSpeed = speed + steer

                max = math.max(math.abs(leftSpeed), math.abs(rightSpeed))
                if max > 1.0:
                    leftSpeed /= max
                    rightSpeed /= max

                robot.leftDrive.setPower(leftSpeed)
                robot.rightDrive.setPower(rightSpeed)

                # Display drive status for the driver.
                telemetry.addData("Err/St", "%5.1f/%5.1f", error, steer)
                telemetry.addData("Target", "%7d:%7d", newLeftTarget, newRightTarget)
                telemetry.addData("Actual", "%7d:%7d", robot.leftDrive.getCurrentPosition(), robot.rightDrive.getCurrentPosition())
                telemetry.addData("Speed", "%5.2f:%5.2f", leftSpeed, rightSpeed)

            # Stop all motion.
            robot.leftDrive.setPower(0)
            robot.rightDrive.setPower(0)

    def gyroTurn(self, speed, angle):
        while opModeIsActive() and not onHeading(speed, angle, P_TURN_COEFF):
            telemetry.update()

        # Stop all motion.
        robot.leftDrive.setPower(0)
        robot.rightDrive.setPower(0)

    def gyroHold(self, speed, angle, holdTime):
        holdTimer = ElapsedTime()
        while opModeIsActive() and (holdTimer.time() < holdTime):
            onHeading(speed, angle, P_TURN_COEFF)
            telemetry.update()

        # Stop all motion.
        robot.leftDrive.setPower(0)
        robot.rightDrive.setPower(0)

    def onHeading(self, speed, angle, PCoeff):
        error = getError(angle)
        steer = getSteer(error, PCoeff)

        if math.abs(error) <= HEADING_THRESHOLD:
            steer = 0.0
            leftSpeed = 0.0
            rightSpeed = 0.0
        else:
            steer = getSteer(error, PCoeff)
            rightSpeed = speed * steer
            leftSpeed = -rightSpeed

        # Send desired speeds to motors.
        robot.leftDrive.setPower(leftSpeed)
        robot.rightDrive.setPower(rightSpeed)

        # Display it for the driver.
        telemetry.addData("Target", "%5.2f", angle)
        telemetry.addData("Err/St", "%5.2f/%5.2f", error, steer)
        telemetry.addData("Speed.", "%5.2f:%5.2f", leftSpeed, rightSpeed)

    def getError(self, targetAngle):
        robotError = targetAngle - self.gyro.getIntegratedZValue()
        while robotError > 180:
            robotError -= 360
        while robotError <= -180:
            robotError += 360

        return robotError

    def getSteer(self, error, PCoeff):
        return Range.clip(error * PCoeff, -1.0, 1.0)
```

Note that this is a direct translation of the Java code into Python and may not be optimal or idiomatic Python code.