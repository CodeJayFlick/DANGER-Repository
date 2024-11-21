Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import logging

class LotteryModule:
    def configure(self):
        self.bind(LotteryTicketRepository).to(MongoTicketRepository)
        self.bind(LotteryEventLog).to(MongoEventLog)
        self.bind(WireTransfers).to(MongoBank)

# Usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    lottery_module = LotteryModule()
    # configure and bind dependencies here...
```
Note that Python does not have a direct equivalent to Java's Guice module, so I've simply defined a `LotteryModule` class with a `configure()` method. The logic inside the `configure()` method is similar to the original Java code.

Also, in Python, we don't need to specify types for variables or function parameters like we do in Java. Additionally, Python's logging module is used instead of Java's equivalent (which I assume was not part of this specific code snippet).