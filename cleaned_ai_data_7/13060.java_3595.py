import threading
import time
from functools import wraps

class Swing:
    SWING_TIMEOUT_SECONDS_PROPERTY = f"ghidra.util.Swing.timeout.seconds"
    SWING_ TIMEOUT_SECONDS_DEFAULT_VALUE = 20

    def __init__(self):
        pass

    @staticmethod
    def isSwingThread():
        if isInHeadlessMode():
            return True
        return threading.main_thread() == threading.current_thread()

    @staticmethod
    def allowSwingToProcessEvents():
        Swing.runNow(lambda: None)
        Swing.runNow(lambda: None)
        Swing.runNow(lambda: None)

    @staticmethod
    def assertSwingThread(errorMessage):
        if not isSwingThread():
            raise Exception(f"Unexpected exception running a task in the Swing Thread: {errorMessage}")
        return True

    @staticmethod
    def runLater(runnable, wait=False, errorMessage=""):
        if isInHeadlessMode() or threading.main_thread() == threading.current_thread():
            runnable()
            return
        if not wait:
            threading.Thread(target=runnable).start()
            return
        try:
            SwingUtilities.invokeLater(runnable)
        except Exception as e:
            Msg.error(Swing, f"Unexpected exception running a task in the Swing Thread: {errorMessage}", e)

    @staticmethod
    def runIfSwingOrRunLater(runnable):
        if isInHeadlessMode():
            runnable()
            return
        if threading.main_thread() == threading.current_thread():
            runnable()
            return
        SwingUtilities.invokeLater(runnable)

    @staticmethod
    def runNow(supplier, timeout=20, unit="seconds"):
        ref = [None]
        try:
            Swing.runLater(lambda: ref[0] = supplier(), wait=True)
            time.sleep(timeout * 1 if unit == "seconds" else (timeout / 60) if unit == "minutes" else timeout)
            return ref[0]
        except Exception as e:
            raise UnableToSwingException(f"Timed-out waiting to run a Swing task--potential deadlock! {e}")

    @staticmethod
    def doRun(runnable, wait=True):
        try:
            runnable()
        finally:
            if not wait:
                return

    @staticmethod
    def isInHeadlessMode():
        # This is equivalent of SystemUtilities.isInHeadlessMode() in Java.
        pass


def SwingUtilities.invokeLater(func):
    threading.Thread(target=func).start()


class UnableToSwingException(Exception):
    pass


# You can use this class like below:
swing = Swing()
if swing.isSwingThread():
    print("This is the event dispatch thread.")
else:
    print("Not on the event dispatch thread.")

def my_task():
    time.sleep(5)
    print("Task completed")

swing.runLater(my_task)

try:
    result = swing.runNow(lambda: 1 + 2, timeout=10, unit="seconds")
except UnableToSwingException as e:
    print(f"Error occurred: {e}")
