Here is the translation of the given Java code into Python:

```Python
class AbstractMessageManager:
    def __init__(self, instance_map):
        self.instance_map = instance_map

    def find_next_instance(self, current_id):
        result = None
        candidate_list = sorted([k for k in self.instance_map if k > current_id and self.instance_map[k].is_alive()])
        if not candidate_list:
            index = min((k for k in self.instance_map if self.instance_map[k].is_alive()))
            result = self.instance_map[index]
        else:
            index = candidate_list[0]
            result = self.instance_map[index]
        return result

class Instance:
    def __init__(self):
        pass
    def is_alive(self):
        # implement your logic here to check if the instance is alive or not
        pass
```

Please note that this translation assumes a few things:

- The `Map` in Java has been replaced with a Python dictionary (`instance_map`) which maps integer keys to instances.
- The `Instance` class in Java has been translated into a similar class in Python, where the `is_alive()` method is supposed to check if an instance is alive or not. You would need to implement this logic according to your specific requirements.

Also note that there are some differences between Python and Java:

- In Python, we don't have explicit constructors like in Java (`__init__` method serves as a constructor).
- The `stream()` function from Java's Stream API is not directly available in Python. Instead, you would use list comprehensions or the built-in functions to achieve similar results.
- Python does not support direct access of dictionary keys using `.keySet()`. You can get all the keys by calling `list(instance_map.keys())` instead.