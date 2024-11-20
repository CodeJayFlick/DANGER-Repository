import threading
from queue import Queue

class BufferedSwingRunner:
    def __init__(self, min_delay=1000, max_delay=30000):
        self.next_runnable = None
        self.min_delay = min_delay
        self.max_delay = max_delay

    def run(self, r):
        if not self.next_runnable:
            threading.Thread(target=self._run).start()
        else:
            self.next_runnable = r
            self.update()

    def _run(self):
        while True:
            current_r = self.prepare_current_r()
            if current_r is None:
                break
            current_r.run()

    def prepare_current_r(self):
        current_r = self.next_runnable
        self.next_runnable = None
        return current_r

    def update(self, delay=None):
        if not delay:
            delay = min(self.max_delay - (threading.time() % self.max_delay), self.min_delay)
        else:
            time.sleep(delay / 1000)

    def run_later(self, r):
        self.next_runnable = r
        self.update()

# Example usage:

class DummyRunnable:
    def __init__(self, runnable=None):
        if runnable is not None:
            threading.Thread(target=runnable).start()
        else:
            pass

def main():
    br = BufferedSwingRunner(min_delay=1000)
    for i in range(5):
        br.run(lambda: print(f"Runnable {i}"))
        time.sleep(1)

if __name__ == "__main__":
    main()

