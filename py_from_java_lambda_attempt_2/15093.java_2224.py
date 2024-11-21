Here is the translation of the Java code into Python:

```Python
import threading
import datetime
import logging

logging.basicConfig(level=logging.INFO)

class App:
    def __init__(self):
        self.counter_date_values = 0
        self.counter_exceptions = 0

    def main(self, args=None):
        counter_date_values = 0
        counter_exceptions = 0

        callable_df = DateFormatCallable("dd/MM/yyyy", "15/12/2015")
        executor = threading.ThreadPool(4)

        futures = []
        for _ in range(4):
            future = executor.submit(callable_df)
            futures.append(future)

        results = [future.result() for future in futures]

        for result in results:
            counter_date_values += print_and_count_dates(result)
            counter_exceptions += print_and_count_exceptions(result)

        logging.info("The List dateList contains {} date values".format(counter_date_values))
        logging.info("The List exceptionList contains {} exceptions".format(counter_exceptions))

    def print_and_count_dates(self, result):
        counter = 0
        for dt in result.date_list:
            counter += 1
            cal = datetime.datetime.strptime(dt, "%d/%m/%Y")
            logging.info("{}.{:02}.{}".format(cal.day, cal.month, cal.year))
        return counter

    def print_and_count_exceptions(self, result):
        counter = 0
        for ex in result.exception_list:
            counter += 1
            logging.info(str(ex))
        return counter


class DateFormatCallable(threading.Thread):
    def __init__(self, format_str, date_str):
        super().__init__()
        self.format_str = format_str
        self.date_str = date_str

    def run(self):
        try:
            dt = datetime.datetime.strptime(self.date_str, "%d/%m/%Y")
            yield dt.strftime(self.format_str)
        except Exception as e:
            raise


if __name__ == "__main__":
    app = App()
    app.main()
```

Please note that Python does not have a direct equivalent to Java's `ThreadLocal` class. However, we can achieve similar behavior by using threads and thread-safe data structures like queues or locks.