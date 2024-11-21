Here is the translation of the given Java code into Python:

```Python
import logging
import time
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO)

class App:
    ROCKET_LAUNCH_LOG_PATTERN = "Space rocket %s launched successfully"

    def __init__(self):
        self.executor = ThreadPoolExecutor()

    @staticmethod
    def lazyval(value, delay_millis):
        async_result = lambda: {
            time.sleep(delay_millis)
            logging.info(f"{value}")
            return value
        }
        return async_result

    @staticmethod
    def callback(name):
        async_callback = lambda value, ex=None: {
            if ex:
                logging.info(f"{name} failed: {ex}")
            else:
                logging.info(f"{name} <{value}>")
        }
        return async_callback

    def main(self):
        # construct a new executor that will run async tasks
        self.executor = ThreadPoolExecutor()

        # start few async tasks with varying processing times, two last with callback handlers
        result1 = self.executor.submit(App.lazyval(10, 500))
        result2 = self.executor.submit(App.lazyval("test", 300))
        result3 = self.executor.submit(App.lazyval(50, 700))
        result4 = self.executor.submit(App.lazyval(20, 400), App.callback("Deploying lunar rover"))
        result5 = self.executor.submit(App.lazyval("callback", 600), App.callback("Deploying lunar rover"))

        # emulate processing in the current thread while async tasks are running in their own threads
        time.sleep(350)  # Oh boy, we are working hard here
        logging.info("Mission command is sipping coffee")

        # wait for completion of the tasks
        result1 = self.executor.submit(App.lazyval(10, 500)).result()
        result2 = self.executor.submit(App.lazyval("test", 300)).result()
        result3 = self.executor.submit(App.lazyval(50, 700)).result()

        result4.result()
        result5.result()

        # log the results of the tasks
        logging.info(self.ROCKET_LAUNCH_LOG_PATTERN % (str(result1)))
        logging.info(self.ROCKET_LAUNCH_LOG_PATTERN % str(result2))
        logging.info(self.ROCKET_LAUNCH_LOG_PATTER % str(result3))

if __name__ == "__main__":
    app = App()
    app.main()

```

Please note that Python does not have direct equivalent of Java's `@Slf4j` annotation, which is used for logging purposes in the given code.