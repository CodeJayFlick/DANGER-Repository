Here is the translation of the Java code into Python:

```Python
import logging
from typing import Any

class RemoteSimpleSeriesReader:
    def __init__(self, source_info: dict):
        self.source_info = source_info
        self.last_timestamp = float('-inf')
        self.cached_batch = None
        self.fetch_result = {'result': None}
        self.handler = GenericHandler(self.source_info['current_node'], self.fetch_result)

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(type(self).__name__)

    def has_next_time_value_pair(self) -> bool:
        if self.cached_batch and self.cached_batch.has_current():
            return True

        self.fetch_batch()
        return self.cached_batch is not None and self.cached_batch.has_current()

    def next_time_value_pair(self) -> dict:
        if not self.has_next_time_value_pair():
            raise NoSuchElementException()

        current_timestamp = self.cached_batch.current_time
        time_value_pair = {
            'timestamp': current_timestamp,
            'value': TsPrimitiveType.get_by_type(
                self.source_info['data_type'], 
                self.cached_batch.current_value
            )
        }
        self.cached_batch.next()
        return time_value_pair

    def current_time_value_pair(self) -> dict:
        if not self.has_next_time_value_pair():
            raise NoSuchElementException()

        return {
            'timestamp': self.cached_batch.current_time,
            'value': TsPrimitiveType.get_by_type(
                self.source_info['data_type'], 
                self.cached_batch.current_value
            )
        }

    def close(self):
        pass

    def fetch_batch(self) -> None:
        if not self.source_info['check_cur_client']:
            self.cached_batch = None
            return

        result = self.fetch_result_async() if self.source_info['config']['use_async_server'] else self.fetch_result_sync()

        self.cached_batch = SerializeUtils.deserialize_batch_data(result)
        if self.logger.getEffectiveLevel() == logging.DEBUG:
            self.logger.debug(
                "Fetched a batch from {}, size:{}".format(self.source_info['current_node'], 
                                                            self.cached_batch.length if self.cached_batch else 0
                )
            )

    def fetch_result_async(self) -> Any:
        with self.fetch_result as result:
            result.value = None

        try:
            client = self.source_info.get_cur_client()
            client.fetch_single_series(
                self.source_info['header'], 
                self.source_info['reader_id'], 
                self.handler
            )
            result.wait(RaftServer.read_operation_timeout_ms)
        except TException as e:
            if not self.source_info.switch_node(False, self.last_timestamp):
                return None

            return self.fetch_result_async()

        except InterruptedException as e:
            Thread.currentThread().interrupt()
            self.logger.warning("Query {} interrupted".format(self.source_info))
            return None

    def fetch_result_sync(self) -> Any:
        client = None
        try:
            client = self.source_info.get_cur_client(RaftServer.read_operation_timeout_ms)
            result = client.fetch_single_series(
                self.source_info['header'], 
                self.source_info['reader_id']
            )
        except TException as e:
            if client is not None:
                client.input_protocol().get_transport().close()

            if not self.source_info.switch_node(False, self.last_timestamp):
                return None

            return self.fetch_result_sync()

        finally:
            if client is not None:
                ClientUtils.put_back_client(client)

    def clear_cur_data_for_test(self) -> None:
        self.cached_batch = None
```

Please note that Python does not have direct equivalent of Java's `AtomicReference` and `synchronized`. The above code uses a dictionary to simulate the behavior.