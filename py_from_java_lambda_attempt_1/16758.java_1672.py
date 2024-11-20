Here is the equivalent Python code:

```Python
import pulsar

class PulsarProducer:
    SERVICE_URL = "pulsar://localhost:6650"
    TOPIC_NAME = ""

    def __init__(self):
        try:
            self.client = pulsar.Client(self.SERVICE_URL)
            self.producer = self.client.new_producer(pulsar.schema.StringSchema())
            self.producer.topic_name(self.TOPIC_NAME)
            self.producer.batcher_builder(pulsar.BatcherBuilder(key_based=True))
            self.producer.hashing_scheme("murmur3_32")
            self.producer.create()
        except pulsar.PulsarClientException as e:
            print(f"Error initializing Pulsar client: {e}")

    def produce(self):
        try:
            for line in ALL_DATA:
                key = line.split(",")[0]
                message = {"key": key, "value": line}
                self.producer.send(key.encode("utf-8"), value=message["value"].encode("utf-8"))
        except pulsar.PulsarClientException as e:
            print(f"Error producing messages: {e}")

    def close(self):
        try:
            self.client.close()
        except pulsar.PulsarClientException as e:
            print(f"Error closing Pulsar client: {e}")


ALL_DATA = [
    "device1,sensor1,2017/10/24 19:30:00,606162908",
    "device1,sensor2,2017/10/24 19:30:00,160161162",
    # ... and so on
]

if __name__ == "__main__":
    producer = PulsarProducer()
    try:
        producer.produce()
    except Exception as e:
        print(f"Error producing messages: {e}")
    finally:
        producer.close()

```

Please note that you need to install the `pulsar` library in Python before running this code. You can do it by using pip:

```shell
pip install pulsar-client
```