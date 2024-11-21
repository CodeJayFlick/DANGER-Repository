import logging
from pika import BasicConsumer, ConnectionParameters, BlockingConnection
from iotdb_python_session import Session
from iotdb_python_tsfile import TSDataType, TSEncoding, CompressionType

class RabbitMQConsumer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def main():
        session = Session('host', 'port', 'user', 'password')
        session.open()
        session.set_storage_group('storage_group')

        for timeseries in Constant.TIMESERIESLIST:
            RabbitMQConsumer.create_timeseries(session, timeseries)

        channel = RabbitMQChannelUtils.get_channel_instance(Constant.CONNECTION_NAME)
        queue_declare_ok = channel.queue_declare(exclusive=True).method
        channel.exchange_declare(exchange=Constant.TOPIC, exchange_type='topic')
        channel.queue_bind(queue=queue_declare_ok.queue, exchange=Constant.TOPIC, routing_key="IoTDB.#")

        def callback(channels, method_frame):
            self.logger.info(f"Received message: {method_frame.body.decode('utf-8')}")
            try:
                RabbitMQConsumer.insert(session, method_frame.body.decode('utf-8'))
            except Exception as e:
                self.logger.error(str(e))

        consumer = BasicConsumer(channel)
        channel.basic_consume(queue=queue_declare_ok.queue, on_message_callback=callback)

    @staticmethod
    def create_timeseries(session, timeseries):
        try:
            session.create_timeseries(timeseries[0], TSDataType.valueOf(timeseries[1]), TSEncoding.valueOf(timeseries[2]), CompressionType.valueOf(timeseries[3]))
        except Exception as e:
            logging.error(str(e))

    @staticmethod
    def insert(session, data):
        device = data.split(',')[0]
        time = int(data.split(',')[1])
        measurements = [x.strip() for x in data.split(',')[2].split(':')]
        types = []
        values = []

        for value_str in data.split(',')[4].split(':'):
            if TSDataType.INT64 == TSDataType.valueOf(value_str):
                values.append(int(value_str))
            elif TSDataType.DOUBLE == TSDataType.valueOf(value_str):
                values.append(float(value_str))
            elif TSDataType.TEXT == TSDataType.valueOf(value_str):
                values.append(value_str)
            else:
                raise Exception(f"Unsupported data type: {value_str}")

        session.insert_record(device, time, measurements, types, values)

if __name__ == "__main__":
    RabbitMQConsumer.main()
