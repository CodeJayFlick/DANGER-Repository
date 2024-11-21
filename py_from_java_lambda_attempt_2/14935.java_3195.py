Here is the translation of the Java code to Python:
```python
import random
import logging

class Data:
    def __init__(self, key):
        self.key = key

class ShardManager:
    def __init__(self):
        self.shard_map = {}
        self.lookup_map = {}

    def store_data(self, data: 'Data') -> int:
        shard_id = self.allocate_shard(data)
        self.lookup_map[data.key] = shard_id
        shard = self.shard_map.get(shard_id)
        shard.store_data(data)
        logging.info(f"{data} is stored in Shard {shard_id}")
        return shard_id

    def allocate_shard(self, data: 'Data') -> int:
        key = data.key
        if key in self.lookup_map:
            return self.lookup_map[key]
        else:
            shard_count = len(self.shard_map)
            return random.randint(1, shard_count - 1)

class LookupShardManager(ShardManager):
    pass

# Example usage:
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    lookup_shard_manager = LookupShardManager()
    data = Data(key=42)
    shard_id = lookup_shard_manager.store_data(data)
    print(f"Data stored in Shard {shard_id}")
```
Note that I've used Python's built-in `logging` module instead of the Java-based SLF4J. Also, I've kept the same class structure and method names as the original code to make it easier to compare with the Java version.