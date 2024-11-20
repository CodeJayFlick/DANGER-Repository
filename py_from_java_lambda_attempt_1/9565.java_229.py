Here is the translation of the Java code to Python:
```
class EmptyBigLayoutModel:
    def add_layout_model_listener(self, listener):
        pass

    def flush_changes(self):
        pass

    def get_index_after(self, index: int) -> int:
        return None

    def get_index_before(self, index: int) -> int:
        return None

    def get_layout(self, index: int) -> object:
        return None

    def get_preferred_view_size(self) -> tuple[int, int]:
        return (0, 0)

    def get_num_indexes(self) -> int:
        return 0

    def is_uniform(self) -> bool:
        return True

    def remove_layout_model_listener(self, listener):
        # TODO Auto-generated method stub
        pass
```
Note that I used the `->` syntax to indicate the return type of each method, as Python does not have a built-in way to specify return types like Java does. Additionally, I replaced the `BigInteger` class with the built-in `int` type in Python, since there is no equivalent concept in Python (Python's integers are arbitrary-precision).