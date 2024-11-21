Here is the translation of the Java code to Python:

```
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class IEvent:
    """Events that fulfill the start stop and list out current status behaviour follow this interface."""

    def start(self):
        pass

    def stop(self):
        pass

    def status(self):
        pass