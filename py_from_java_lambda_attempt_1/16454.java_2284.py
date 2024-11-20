Here is the translation of the Java code into Python:

```Python
import logging
from concurrent.futures import ThreadPoolExecutor, Future
from queue import Queue

class AsyncDataLogApplier:
    def __init__(self, embedded_applier: 'AsyncDataLogApplier', name: str):
        self.embedded_applier = embedded_applier
        self.consumer_map = {}
        self.consumer_pool = ThreadPoolExecutor(max_workers=Runtime.getRuntime().availableProcessors())
        self.name = name

    @staticmethod
    def get_logger():
        return logging.getLogger(AsyncDataLogApplier.__name__)

    def close(self):
        self.consumer_pool.shutdown()

    def apply(self, log: 'Log'):
        if isinstance(log, PhysicalPlanLog):
            plan_key = self.get_plan_key(log)
            provide_log_to_consumers(plan_key, log)
            return

        logging.debug(f"{self.name}: {log} is waiting for consumers to drain")
        start_time = Statistic.RAFT_SENDER_COMMIT_TO_CONSUMER_LOGS.get_operation_start_time()
        drain_consumers()
        apply_internal(log)
        Statistic.RAFT_SENDER_COMMIT_EXCLUSIVE_LOGS.cal_operation_cost_time_from_start(start_time)

    def get_log_key(self, log: 'Log') -> PartialPath:
        if isinstance(log, PhysicalPlanLog):
            physical_plan_log = log
            plan = physical_plan_log.get_plan()
            return self.get_plan_key(plan)
        elif isinstance(log, CloseFileLog):
            close_file_log = log
            partial_path = None
            try:
                partial_path = PartialPath(close_file_log.get_storage_group_name())
            except IllegalPathException as e:
                # unreachable
                pass
            return partial_path

    def get_plan_key(self, plan: 'PhysicalPlan') -> PartialPath:
        return self.get_plan_sg(plan)

    @staticmethod
    def get_plan_sg(plan: 'PhysicalPlan') -> PartialPath:
        sg_path = None
        if isinstance(plan, InsertMultiTabletPlan):
            device_id = plan.get_first_device_id()
            sg_path = IoTDB.meta_manager.get_belonged_storage_group(device_id)
        elif isinstance(plan, InsertRowsPlan):
            path = plan.get_first_device_id()
            sg_path = IoTDB.meta_manager.get_belonged_storage_group(path)
        elif isinstance(plan, InsertPlan):
            device_id = plan.get_prefix_path()
            sg_path = IoTDB.meta_manager.get_belonged_storage_group(device_id)
        elif isinstance(plan, CreateTimeSeriesPlan):
            path = plan.get_path()
            sg_path = IoTDB.meta_manager.get_belonged_storage_group(path)

    def provide_log_to_consumers(self, partial_path: PartialPath, log: 'Log'):
        if Timer.ENABLE_INSTRUMENTING:
            log.set_enqueue_time(System.nanoTime())
        self.consumer_map[partial_path] = DataLogConsumer(self.name + "-" + str(partial_path)).accept(log)

    @staticmethod
    def drain_consumers():
        while not all_consumers_empty():
            try:
                consumer_empty_condition.wait(5)
            except InterruptedException as e:
                Thread.currentThread().interrupt()
                return

    @staticmethod
    def all_consumers_empty() -> bool:
        for consumer in list(self.consumer_map.values()):
            if not consumer.is_empty():
                logging.debug(f"Consumer {consumer} is not empty")
                return False
        return True

    def apply_internal(self, log: 'Log'):
        start_time = Statistic.RAFT_SENDER_DATA_LOG_APPLY.get_operation_start_time()
        self.embedded_applier.apply(log)
        if Timer.ENABLE_INSTRUMENTING:
            Statistic.RAFT_SENDER_DATA_LOG_APPLY.cal_operation_cost_time_from_start(start_time)

    class DataLogConsumer(threading.Thread):
        def __init__(self, name: str):
            super().__init__()
            self.name = name
            self.log_queue = Queue(4096)
            self.last_log_index = 0
            self.last_applied_log_index = 0

        @staticmethod
        def run(self):
            while not Thread.currentThread().is_interrupted():
                try:
                    log = self.log_queue.get()
                    Statistic.RAFT_SENDER_IN_APPLY_QUEUE.cal_operation_cost_time_from_start(log.enqueue_time)
                    apply_internal(log)
                    if is_empty():
                        consumer_empty_condition.notify_all()
                except InterruptedException as e:
                    Thread.currentThread().interrupt()
                    break
                except Exception as e:
                    logging.error("DataLogConsumer exits", e)

        def accept(self, log: 'Log'):
            if self.future and (self.future.cancel() or self.future.done()):
                try:
                    self.future.result()
                except InterruptedException as e:
                    logging.error("Last applier thread exits unexpectedly", e)
                except ExecutionException as e:
                    logging.error("Last applier thread exits unexpectedly", e)

            self.log_queue.put(log)
            if not is_empty():
                last_log_index = log.current_log_index
                try:
                    last_applied_log_index = log.get_current_log_index()
                except Exception as e:
                    pass

        def __str__(self):
            return f"DataLogConsumer{{log_queue={self.log_queue.qsize()}, last_log_index={self.last_log_index}, " \
                   f"last_applied_log_index={self.last_applied_log_index}, name='{self.name}'}}"
```

Please note that Python does not have a direct equivalent to Java's `synchronized` keyword. Instead, you can use locks or the `threading.Lock` class from the standard library.

Also, in this translation, I used the built-in `logging` module for logging purposes and replaced some of the static methods with instance methods as per Python conventions.