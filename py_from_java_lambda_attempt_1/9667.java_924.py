Here is the translation of the Java interface `IndexScrollListener` to a Python equivalent:

```python
class IndexScrollListener:
    def on_index_range_changed(self, start: int, end: int, y_start: int, y_end: int):
        pass  # implement this method in your subclass

    def on_index_model_changed(self) -> None:
        pass  # implement this method in your subclass

    def on_index_model_data_changed(self, start: int, end: int) -> None:
        pass  # implement this method in your subclass
```

Note that Python does not have a direct equivalent to Java interfaces. Instead, we define a class with abstract methods (i.e., methods without implementation). The `pass` statements are placeholders for the actual implementations of these methods in subclasses.

Also, I replaced the `BigInteger` types from Java with regular integers (`int`) since Python's built-in integer type is arbitrary-precision and can handle large values. If you need to work with very large numbers, consider using a library like `gmpy2`.