import logging
from typing import List, Dict, Any

class IoTDBSink:
    def __init__(self, options: 'IoTDBSinkOptions', schema: 'IoTSerailizationSchema') -> None:
        self.options = options
        self.schema = schema
        self.batch_list = []
        self.timeseries_option_map = {}
        for timeseries_option in options.get_timeseries_options():
            self.timeseries_option_map[timeseries_option.path] = timeseries_option

    def open(self, parameters: Any) -> None:
        self.init_session()
        self.init_scheduler()

    def init_session(self) -> None:
        self.pool = SessionPool(
            host=self.options.host,
            port=self.options.port,
            user=self.options.user,
            password=self.options.password,
            pool_size=self.options.session_pool_size
        )

    def init_scheduler(self) -> None:
        if self.batch_size > 0:
            import schedule, time

            def flush():
                try:
                    self.flush()
                except Exception as e:
                    logging.error("flush error", e)

            schedule.every(3).seconds.do(flush)
            while True:
                schedule.run_pending()
                time.sleep(1)

    def set_session_pool(self, pool: 'SessionPool') -> None:
        self.pool = pool

    def invoke(self, input: Any) -> None:
        event = self.schema.serialize(input)
        if event is None:
            return
        if self.batch_size > 0:
            with lock(self.batch_list):
                self.batch_list.append(event)
                if len(self.batch_list) >= self.batch_size:
                    self.flush()
                    return

        convert_text(event.device, event.measurements, event.values)

    def flush(self) -> None:
        if self.batch_size > 0:
            with lock(self.batch_list):
                if len(self.batch_list) > 0:
                    device_ids = []
                    timestamps = []
                    measurements_list = []
                    types_list = []
                    values_list = []

                    for event in self.batch_list:
                        convert_text(event.device, event.measurements, event.values)
                        device_ids.append(event.device)
                        timestamps.append(event.timestamp)
                        measurements_list.append(event.measurements)
                        types_list.append(event.types)
                        values_list.append(event.values)

                    self.pool.insert_records(device_ids, timestamps, measurements_list, types_list, values_list)
                    logging.debug("send event successfully")
                    self.batch_list.clear()

    def with_batch_size(self, batch_size: int) -> 'IoTDBSink':
        if batch_size < 0:
            raise ValueError
        self.batch_size = batch_size
        return self

    def with_flush_interval_ms(self, flush_interval_ms: int) -> 'IoTDBSink':
        if flush_interval_ms <= 0:
            raise ValueError
        self.flush_interval_ms = flush_interval_ms
        return self

    def with_session_pool_size(self, session_pool_size: int) -> 'IoTDBSink':
        if session_pool_size <= 0:
            raise ValueError
        self.session_pool_size = session_pool_size
        return self

    def close(self) -> None:
        if self.pool is not None:
            try:
                self.flush()
            except Exception as e:
                logging.error("flush error", e)
            self.pool.close()

        import threading
        lock = threading.Lock()

class Event:
    def __init__(self, device: str, timestamp: int, measurements: List[str], values: List[Any]) -> None:
        self.device = device
        self.timestamp = timestamp
        self.measurements = measurements
        self.values = values

def convert_text(device: str, measurements: List[str], values: List[Any]) -> None:
    if device is not None and measurements is not None and values is not None and len(measurements) == len(values):
        for i in range(len(measurements)):
            measurement = f"{device}/{measurements[i]}"
            timeseries_option = self.timeseries_option_map.get(measurement)
            if timeseries_option is not None and TSDataType.TEXT.equals(timeseries_option.data_type):
                values[i] = "'" + str(values[i]) + "'"
