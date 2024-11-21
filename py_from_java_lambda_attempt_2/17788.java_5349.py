Here is the translation of the given Java code into Python:

```Python
import threading
import time
from random import randint

class Worker(threading.Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        try:
            while True:
                seed = atomic_long.get() + 1
                if seed > total_lines:
                    break
                time_value = randint(0, (seed % num_devices) - 1)
                delta_object = devices[time_value]
                ts_record = get_record(delta_object, time_value)
                storage_engine.insert(ts_record)
        except Exception as e:
            print(e)

class FileNodeManagerBenchmark:

    numOfWorker = 10
    numOfDevice = 10
    numOfMeasurement = 10
    total_lines = 10000000

    devices = ["root.bench" + str(i) for i in range(numOfDevice)]
    measurements = [str(i) for i in range(numOfMeasurement)]

    atomic_long = threading.Value('i', 0)

    def prepare(self):
        manager = MManager()
        manager.set_storage_group(PartialPath("root.bench"))
        for device in devices:
            for measurement in measurements:
                ts_path = PartialPath(device + "." + measurement)
                manager.create_timeseries(ts_path, TSDataType.INT64, TSEncoding.PLAIN)

    def tearDown(self):
        EnvironmentUtils.clean_env()

    def get_record(self, delta_object_id, timestamp):
        ts_record = TSRecord(timestamp, delta_object_id)
        for measurement in measurements:
            ts_record.add_tuple(LongDataPoint(measurement, timestamp))
        return ts_record

    def main(self):

        self.tearDown()
        self.prepare()
        start_time = time.time()

        threads = []
        for i in range(numOfWorker):
            worker = Worker()
            worker.start()
            threads.append(worker)

        for thread in threads:
            thread.join()

        end_time = time.time()
        print("Elapsed time: " + str(end_time - start_time) + "ms")
        self.tearDown()


if __name__ == "__main__":
    benchmark = FileNodeManagerBenchmark()
    benchmark.main()
```

Please note that Python does not have direct equivalent of Java's `AtomicLong` and `CountDownLatch`. We are using threading.Value('i', 0) to simulate the behavior of AtomicLong. Also, we are manually handling threads in this code as there is no direct equivalent of CountDownLatch in Python.