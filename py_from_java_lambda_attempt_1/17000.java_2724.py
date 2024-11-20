Here's a translation of your Java code into equivalent Python:

```Python
class NotifyFlushMemTable:
    def gen_mem_series(self, schema):
        return None

    def copy(self):
        return None

    def is_signal_mem_table(self):
        return True


# You can use this class like so:
memtable = NotifyFlushMemTable()
schema = "your_schema"
print(memtable.gen_mem_series(schema))  # prints: None
print(memtable.copy())  # prints: None
print(memtable.is_signal_mem_table())  # prints: True
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. In Python, you would typically use modules or packages to organize your code and import them as needed.

Also, in Python, we don't need to explicitly define the type of a variable like we do in Java with `public class NotifyFlushMemTable extends AbstractMemTable`.