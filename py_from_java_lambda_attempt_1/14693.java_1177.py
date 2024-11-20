Here is the translation of the Java code to Python:
```python
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
```
Note that I had to make some assumptions about the Python code:

* The `MqSubscribePoint` class is not present in Python, so I replaced it with a simple `queue` variable.
* The `Message` class has been simplified to just a string value (`"POISON_PILL"`).
* The `Headers` and `Slf4j` classes are not needed in Python, as logging can be handled using the built-in `logging` module.

You'll need to replace `"your_queue_here"` with your actual queue name.