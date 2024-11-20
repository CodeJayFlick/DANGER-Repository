import logging

class Consumer:
    def __init__(self, name: str, queue):
        self.name = name
        self.queue = queue

    def consume(self):
        while True:
            try:
                msg = self.queue.take()
                if msg == "POISON_PILL":
                    logging.info("Consumer {} receive request to terminate.".format(self.name))
                    break
                sender = msg.get_header("SENDER")
                body = msg.get_body()
                logging.info("Message [{}] from [{}] received by [{}].".format(body, sender, self.name))
            except KeyboardInterrupt:
                # allow thread to exit
                pass
            except Exception as e:
                logging.error("Exception caught.", e)
                return

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python consumer.py <queue_name> <consumer_name>")
        sys.exit(1)

    queue = "your_queue_here"  # replace with your actual queue name
    name = sys.argv[2]
    c = Consumer(name, queue)
    c.consume()
