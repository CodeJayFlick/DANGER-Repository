Here is the translation of the Java interface `ChannelHandler` into a Python class:

```python
class ChannelHandler:
    def handle_channel_read(self, channel: 'AbstractNioChannel', read_object: object, key: 'SelectionKey'):
        pass  # implement your application logic here
```

Note that I've used type hints for the method parameters to indicate their expected types. In Python, these are not enforced at runtime, but they can be useful for documentation and static analysis purposes.

Also note that there is no direct equivalent of Java's `interface` in Python; instead, we define a class with abstract methods (i.e., methods without implementation). The `pass` statement inside the method indicates that this method does nothing when called. You would need to implement your application logic within this method.