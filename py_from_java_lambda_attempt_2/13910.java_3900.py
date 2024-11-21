Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class MessagingDatabase:
    def __init__(self):
        self.data = {}

    def add(self, r: dict) -> dict:
        return {**self.data, **{r['reqId']: r}}

    def get(self, requestId: str) -> dict or None:
        return self.data.get(requestId)
```
Note that I've made the following changes:

* Removed the package declaration and imports, as they are not necessary in Python.
* Replaced the `Hashtable` with a simple dictionary (`{}`).
* Changed the method signatures to use Python's built-in types (e.g. `dict`, `str`) instead of Java's.
* Simplified the implementation of the `add` method using dictionary concatenation (`**` operator).
* In the `get` method, I've changed the return type to `dict or None` since we're returning a value from the dictionary if it exists, and `None` otherwise.

This Python code defines a class `MessagingDatabase` with two methods: `add` and `get`. The `add` method takes a message request as input (represented as a dictionary) and adds it to the internal data structure. The `get` method returns the message request associated with a given request ID, or `None` if no such request exists.