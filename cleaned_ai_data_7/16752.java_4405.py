import kafka
from logging import Logger
from logging.config import dictConfigFromDict
from threading import Thread
import time

class KafkaProducer:
    def __init__(self):
        self.producer = kafka.KafkaProducer(bootstrap_servers=['127.0.0.1:9092'])

    def produce(self, data):
        for i in range(len(data)):
            key = str(i)
            value = data[i]
            future = self.producer.send_and_wait('topic', key.encode(), value.encode())
            print(future.value.decode())

    def close(self):
        self.producer.close()

if __name__ == "__main__":
    kafka_producer = KafkaProducer()
    all_data = ['data1', 'data2', ...]  # replace with your data
    threads = []
    
    for i in range(len(all_data)):
        t = Thread(target=kafka_producer.produce, args=(all_data,))
        threads.append(t)
        t.start()

    for thread in threads:
        thread.join()
        
    kafka_producer.close()
