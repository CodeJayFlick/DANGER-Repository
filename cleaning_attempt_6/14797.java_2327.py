import logging
import time
from threading import Thread

class App:
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.is_running = False

    def start(self):
        if not self.is_running:
            self.is_running = True
            # Start the application using the provided dispatcher
            pass  # This should be implemented based on the actual logic of your App class

    def stop(self):
        if self.is_running:
            self.is_running = False
            # Stop the application
            pass  # This should be implemented based on the actual logic of your App class


class AppClient(Thread):
    def __init__(self, app=None):
        super().__init__()
        self.app = app

    def run(self):
        if self.app:
            try:
                time.sleep(2)  # Artificial delay
            except Exception as e:
                logging.error("sleep interrupted", e)
            finally:
                self.app.stop()


def test_app_using_thread_pool_dispatcher():
    logging.info("testAppUsingThreadPoolDispatcher start")
    app = App(ThreadPoolDispatcher())
    app.start()
    assert app is not None

    client = AppClient(app)
    client.start()

    time.sleep(2)  # Artificial delay
    client.stop()
    app.stop()
    logging.info("testAppUsingThreadPoolDispatcher stop")


def test_app_using_same_thread_dispatcher():
    logging.info("testAppUsingSameThreadDispatcher start")
    app = App(SameThreadDispatcher())
    app.start()
    assert app is not None

    client = AppClient(app)
    client.start()

    time.sleep(2)  # Artificial delay
    client.stop()
    app.stop()
    logging.info("testAppUsingSameThreadDispatcher stop")


if __name__ == "__main__":
    test_app_using_thread_pool_dispatcher()
    test_app_using_same_thread_dispatcher()
