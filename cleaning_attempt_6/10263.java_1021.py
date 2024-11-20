import time
import threading

class TimerCallback:
    def __init__(self):
        self.i = 0

    def timer_fired(self):
        print(f"A: {self.i}")
        if self.i == 20:
            return False
        self.i += 1
        return True


def get_ghidra_timer(initial_delay, delay, callback=None):
    if threading.get_ident() in [threading._headless_mode_thread]:
        return GhidraSwinglessTimer(initial_delay, delay, callback)
    return GhidraSwingTimer(initial_delay, delay, callback)


class GhidraTimer:
    def __init__(self, initial_delay, delay):
        self.initial_delay = initial_delay
        self.delay = delay

    def set_initial_delay(self, value):
        self.initial_delay = value

    def set_timer_callback(self, callback):
        self.callback = callback

    def start(self):
        threading.Thread(target=self.run).start()

    def run(self):
        if not self.callback:
            return
        while True:
            time.sleep(self.delay)
            if not self.callback.timer_fired():
                break


def main():
    import os
    os.environ['HEADLESS_PROPERTY'] = 'true'

    t1 = get_ghidra_timer(0.5, 0.5, None)
    t1.set_initial_delay(0.5)
    callback1 = TimerCallback()
    t1.set_timer_callback(callback1)
    t1.start()

    t2 = get_ghidra_timer(0.25, 1.0, None)
    t2.set_initial_delay(0.25)
    callback2 = TimerCallback()
    t2.set_timer_callback(callback2)
    t2.start()

    time.sleep(20)


if __name__ == "__main__":
    main()
