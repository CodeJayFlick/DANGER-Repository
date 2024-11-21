import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import math

class MultithreadedBenchmark:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Multithreading inference")

    def predict(self, arguments: dict, metrics: dict, iteration: int) -> list or None:
        try:
            # Measure memory before loading model
            MemoryTrainingListener.collect_memory_info(metrics)

            engine = Engine.get_engine(arguments["engine"])
            devices = engine.get_devices(arguments["max_gpus"])
            num_of_threads = arguments["threads"]
            delay = arguments["delay"]

            models = []
            callables = []

            for device in devices:
                model = load_model(arguments, metrics, device)
                models.append(model)

                for i in range(num_of_threads // len(devices)):
                    callable = PredictorCallable(model, metrics, iteration, i, i == 0)
                    callables.append(callable)

            result = None
            executor_service = ThreadPoolExecutor(max_workers=num_of_threads)

            # Measure memory before worker kickoff
            MemoryTrainingListener.collect_memory_info(metrics)

            success_threads = 0

            for callable in callables:
                callable.warmup()

            metrics["start"] = time.time()
            try:
                if delay > 0:
                    futures = []
                    for i, callable in enumerate(callables):
                        futures.append(executor_service.submit(callable))
                        time.sleep(delay)
                    results = [future.result() for future in as_completed(futures)]
                else:
                    results = list(executor_service.map(lambda x: x.result(), callables))

                for result in results:
                    if result is not None:
                        success_threads += 1

            except (Exception, KeyboardInterrupt):
                self.logger.error("", *sys.exc_info())
            finally:
                executor_service.shutdown()
                metrics["end"] = time.time()

        except Exception as e:
            self.logger.error("", e)

    def close(self):
        pass


class PredictorCallable:
    def __init__(self, model: ZooModel, metrics: dict, iteration: int, worker_id: int, collect_memory: bool):
        self.predictor = model.new_predictor()
        self.metrics = metrics
        self.counter = AtomicInteger(iteration)
        self.worker_id = f"{worker_id:02d}"
        self.collect_memory = collect_memory

    def call(self) -> list or None:
        result = None
        count = 0
        remaining = self.counter.get()

        while (remaining > 0 and result is None):
            try:
                result = self.predictor.predict(None)
            except Exception as e:
                # stop immediately when we find any exception
                self.counter.set(0)
                raise

            if self.collect_memory:
                MemoryTrainingListener.collect_memory_info(self.metrics)

            processed = self.counter.get() - remaining + 1
            self.logger.trace(f"Worker-{self.worker_id}: {processed} iteration finished.")
            if processed % (10 ** math.floor(math.log10(processed))) == 0 or processed == self.counter.get():
                self.logger.info("Completed {} requests", processed)

        self.logger.debug(f"Worker-{self.worker_id}: finished.")

    def warmup(self) -> None:
        try:
            self.predictor.predict(None)
        except Exception as e:
            raise

    def close(self):
        self.predictor.close()
