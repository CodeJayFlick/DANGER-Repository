import time
import threading

class BallItem:
    def __init__(self):
        self.twin = None

    def set_twin(self, twin):
        self.twin = twin

    def click(self):
        print("Ball item clicked")

    def stop_me(self):
        pass  # no equivalent in Python


class BallThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.twin = None
        self.stop_request = False

    def set_twin(self, twin):
        self.twin = twin

    def run(self):
        while not self.stop_request:
            time.sleep(0.75)  # equivalent to waiting()
            if self.twin is not None and hasattr(self.twin, 'click'):
                self.twin.click()

    def stop_me(self):
        self.stop_request = True


def main():
    ball_item = BallItem()
    ball_thread = BallThread()

    ball_item.set_twin(ball_thread)
    ball_thread.set_twin(ball_item)

    ball_thread.start()

    time.sleep(0.75)  # equivalent to waiting()

    ball_item.click()

    time.sleep(0.75)  # equivalent to waiting()

    ball_item.click()

    time.sleep(0.75)  # equivalent to waiting()

    ball_thread.stop_me()


if __name__ == "__main__":
    main()
