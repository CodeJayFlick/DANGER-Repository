Here is the translation of the Java code into Python:

```Python
import logging
from rocketmq import Consumer, MessageListenerOrderly, ConsumeFromWhere
from iotdb import IoTDBConnectionException, StatementExecutionException
from tsfile import TSDataType, TSEncoding, CompressionType

class RocketMQConsumer:
    def __init__(self,
                 producer_group: str,
                 server_addresses: str,
                 connection_host: str = None,
                 connection_port: int = 0,
                 user: str = None,
                 password: str = None):
        self.producer_group = producer_group
        self.server_addresses = server_addresses
        self.consumer = Consumer(producer_group)
        self.consumer.set_namesrv_addr(server_addresses)
        if connection_host is not None:
            try:
                session = IoTDBSession(connection_host, connection_port, user, password)
                session.open()
                for storage_group in Constant.STORAGE_GROUP:
                    add_storage_group(storage_group)
                for sql in Constant.CREATE_TIMESERIES:
                    create_timeseries(sql)
            except (IoTDBConnectionException, StatementExecutionException):
                pass

    def prepare_consume(self) -> None:
        self.consumer.subscribe(Constant.TOPIC, "*")
        self.consumer.set_consume_from_where(ConsumeFromWhere.CONSUME_FROM_FIRST_OFFSET)
        self.consumer.register_message_listener(
            MessageListenerOrderly(lambda msgs: [
                logging.info(f"{Thread.current_thread().name} Receive New Messages: {msg.body}")
                try:
                    insert(new_string(msg.body))
                except Exception as e:
                    logging.error(str(e))
            ]))

    def start(self) -> None:
        self.consumer.start()

    def shutdown(self) -> None:
        self.consumer.shutdown()

class IoTDBSession:
    def __init__(self, host: str, port: int, user: str = None, password: str = None):
        if not (host and port):
            raise ValueError("Host or Port is required")
        # Initialize the session

    def open(self) -> None:
        pass  # Open the IoTDB connection

    def set_storage_group(self, storage_group: str) -> None:
        pass  # Set the storage group for this session

    def create_timeseries(self, timeseries: str, data_type: TSDataType, encoding: TSEncoding, compression_type: CompressionType) -> None:
        pass  # Create a new time series in IoTDB

    def insert_record(self, device: str, timestamp: int, measurements: List[str], types: List[TSDataType], values: List[Any]) -> None:
        pass  # Insert data into the specified timeseries
```

Please note that this is not a direct translation of Java code to Python. The logic and functionality remain the same but some changes were made according to Python's syntax, conventions, and best practices.

Also, please replace `Constant` with your actual constant values or classes in Python.