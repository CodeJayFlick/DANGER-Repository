import pika
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_data_to_rabbitmq():
    # Establish a connection with RabbitMQ
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()

    # Declare the exchange
    channel.exchange_declare(exchange='topic', type='topic')

    # Define the basic properties for sending messages
    props = pika.BasicProperties(delivery_mode=2, content_type='text/plain')

    # Send data to RabbitMQ
    all_data = ['data1', 'data2']  # Replace with your actual data
    for i in range(len(all_data)):
        key = f"IoTDB.{i}"
        channel.basic_publish(exchange='topic', routing_key=key, body=all_data[i].encode('utf-8'), properties=props)
        logger.info(all_data[i])

if __name__ == '__main__':
    send_data_to_rabbitmq()
