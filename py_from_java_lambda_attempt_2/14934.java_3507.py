Here is the translation of the Java code to Python:
```
import logging

class ShardManager:
    def __init__(self):
        self.shard_map = {}

    def store_data(self, data: dict) -> int:
        shard_id = self.allocate_shard(data)
        shard = self.shard_map.get(shard_id)
        if shard is None:
            raise ValueError(f"Shard {shard_id} does not exist")
        shard.store_data(data)
        logging.info(f"{data['key']} is stored in Shard {shard_id}")
        return shard_id

    def allocate_shard(self, data: dict) -> int:
        shard_count = len(self.shard_map)
        hash_value = hash(data["key"]) % shard_count
        if hash_value == 0:
            hash_value += shard_count
        return hash_value


class Data:
    def __init__(self, key):
        self.key = key

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sm = ShardManager()
    data1 = Data(42)
    data2 = Data(21)
    sm.store_data(data1.to_dict())
    sm.store_data(data2.to_dict())

class Shard:
    def store_data(self, data: dict):
        # implement shard storage logic here
        pass

# Example usage:
shard_map = {}
for i in range(5):
    shard_map[i] = Shard()

sm = ShardManager()
data1 = Data(42)
data2 = Data(21)

print(sm.store_data(data1.to_dict()))
print(sm.store_data(data2.to_dict()))

```
Note that I had to make some assumptions about the `Data` class and its methods, as well as the `Shard` class. In Java, these classes seem to be part of a larger system, but in Python, they are standalone classes for demonstration purposes only.

Also, please note that this is not an exact translation, as Python has different syntax and semantics than Java. I tried my best to preserve the original logic while adapting it to Python's style.