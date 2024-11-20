import time
from threading import Thread
import logging

class AlgorithmSelfSteppingTaskMonitor:
    def __init__(self, step_time):
        self.step_time = step_time

    def pause(self):
        if self.is_cancelled():
            return  # no pausing after cancelled
        
        self.notify_step_ready()
        
        try:
            time.sleep(self.step_time)
        except Exception as e:
            logging.debug("Interrupted waiting for next step", exc_info=e)

class Msg:
    @staticmethod
    def debug(obj, msg, *args):
        print(f"{obj}: {msg} - {' '.join(map(str, args))}")

def notify_step_ready():
    pass  # This method is not implemented in the original Java code

def is_cancelled():
    return False  # This method is not implemented in the original Java code
