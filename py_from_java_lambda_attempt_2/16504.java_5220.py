Here is the translation of the given Java code into Python:

```Python
import hashlib

class SlotStrategy:
    def calculate_slot_by_time(self, storage_group_name: str, timestamp: int, max_slot_num: int) -> int:
        partition_num = StorageEngine.get_time_partition(timestamp)
        return self.calculate_slot_by_partition_num(storage_group_name, partition_num, max_slot_num)

    def calculate_slot_by_partition_num(
            self, storage_group_name: str, partition_id: int, max_slot_num: int
    ) -> int:
        hash_value = hashlib.md5(f"{storage_group_name}{partition_id}".encode()).hexdigest()
        return abs(int(hash_value, 16)) % max_slot_num


class DefaultStrategy(SlotStrategy):
    def calculate_slot_by_time(self, storage_group_name: str, timestamp: int, max_slot_num: int) -> int:
        partition_num = StorageEngine.get_time_partition(timestamp)
        return self.calculate_slot_by_partition_num(storage_group_name, partition_num, max_slot_num)

    def calculate_slot_by_partition_num(
            self, storage_group_name: str, partition_id: int, max_slot_num: int
    ) -> int:
        hash_value = hashlib.md5(f"{storage_group_name}{partition_id}".encode()).hexdigest()
        return abs(int(hash_value, 16)) % max_slot_num


class StorageEngine:
    @staticmethod
    def get_time_partition(timestamp: int) -> int:
        # This method should be implemented based on the actual logic of getting time partition.
        pass

# Usage example:

default_strategy = DefaultStrategy()
print(default_strategy.calculate_slot_by_time("storage_group_name", 1643723400, 100))
```

Please note that you need to implement `StorageEngine.get_time_partition` method according to your specific requirements.