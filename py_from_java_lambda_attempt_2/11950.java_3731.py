Here is the translation of the Java code to Python:
```
class FunctionTagMappingAdapterNoTable:
    def __init__(self):
        pass

    # PUBLIC METHODS

    def get_record(self, function_id: int, tag_id: int) -> None:
        return None

    def create_function_tag_record(self, function_id: int, tag_id: int) -> None:
        raise NotImplementedError("create record not supported")

    def remove_function_tag_record(self, function_id: int, tag_id: int) -> None:
        raise NotImplementedError("remove record not supported")

    def remove_function_tag_record_by_tag_id(self, tag_id: int) -> None:
        raise NotImplementedError("remove record not supported")

    def get_records_by_function_id(self, function_id: int) -> list[None]:
        return []

    def is_tag_assigned(self, id: int) -> bool:
        return False

    def get_all_records(self) -> list[None]:
        return []
```
Note that I've used Python's built-in `list` type to represent the record iterators in Java. In Python, you don't need to explicitly implement an iterator interface like you do in Java.

Also, I've replaced the `throws IOException` clauses with simply returning `None`, since Python doesn't have a direct equivalent of Java's checked exceptions. If you want to raise an exception instead, you can use the `raise` statement as shown in some methods above.