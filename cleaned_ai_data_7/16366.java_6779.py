import logging
from threading import Thread
from queue import Queue
from PIL import Image
import os

class ConceptWebcam:
    def __init__(self):
        self.TAG = "Webcam Sample"
        self.secondsPermissionTimeout = float('inf')
        self.cameraManager = None
        self.cameraName = None
        self.camera = None
        self.captureSession = None
        self.frameQueue = Queue()
        self.captureCounter = 0
        self.captureDirectory = os.path.join(os.environ['ROBOT_DATA_DIR'], 'captures')

    def runOpMode(self):
        logging.info('Press Play to start')
        while not opmodeIsActive():
            if gamepad1.a and not buttonPressSeen:
                captureWhenAvailable = True
            buttonPressSeen = gamepad1.a

            if captureWhenAvailable:
                frame = self.frameQueue.get()
                if frame is not None:
                    captureWhenAvailable = False
                    self.onNewFrame(frame)

        logging.info('Stopped...')

    def onNewFrame(self, frame):
        self.saveBitmap(frame)
        frame.close()

    def initializeFrameQueue(self, capacity):
        self.frameQueue = Queue(maxsize=capacity)

    def openCamera(self):
        if self.camera is not None:
            return

        deadline = Deadline(0)  # seconds
        camera = self.cameraManager.requestPermissionAndOpenCamera(deadline, self.cameraName)
        if camera is None:
            logging.error('camera not found or permission to use not granted: %s', self.cameraName)

    def startCamera(self):
        if self.captureSession is not None:
            return

        imageFormat = Image.EXTENSION_YUY2
        size = (0, 0)
        fps = 30

        try:
            cameraCharacteristics = self.cameraName.getCameraCharacteristics()
            if not contains(cameraCharacteristics.getAndroidFormats(), imageFormat):
                logging.error('image format not supported')
                return

            size = cameraCharacteristics.getDefaultSize(imageFormat)
            fps = cameraCharacteristics.getMaxFramesPerSecond(imageFormat, size)

            synchronizer = ContinuationSynchronizer()
            try:
                captureSession = self.camera.createCaptureSession(Continuation(self.callbackHandler, CameraCaptureSession.StateCallbackDefault()))
                captureSession.startCapture(CameraCaptureRequest(imageFormat, size, fps), onNewFrame)
                synchronizer.finish(captureSession)
            except (CameraException, RuntimeError) as e:
                logging.error('exception starting camera: %s', str(e))
                error = 'exception starting camera'
        finally:
            self.captureSession = None

    def stopCamera(self):
        if self.captureSession is not None:
            self.captureSession.stopCapture()
            self.captureSession.close()

    def closeCamera(self):
        self.stopCamera()
        if self.camera is not None:
            self.camera.close()

    def saveBitmap(self, bitmap):
        file = os.path.join(self.captureDirectory, f'webcam-frame-{self.captureCounter}.jpg')
        try:
            with open(file, 'wb') as output_stream:
                bitmap.save(output_stream, format='JPEG', quality=100)
            logging.info('captured %s', file)
        except (IOError) as e:
            logging.error('exception in saveBitmap(): %s', str(e))

    def contains(self, array, value):
        for i in array:
            if i == value:
                return True
        return False

# usage example
concept_webcam = ConceptWebcam()
while not opmodeIsActive():
    concept_webcam.runOpMode()

