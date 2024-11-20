class Data:
    def __init__(self, id: int, name: str, data_type: str):
        self.id = id
        self.name = name
        self.data_type = data_type


class Shard:
    def __init__(self, shard_id: int):
        self.shard_id = shard_id

    def clear_data(self) -> None:
        pass  # This method is not implemented in the Java code. I've left it as a placeholder.


class LookupShardManager:
    def __init__(self):
        self.shards = []

    def add_new_shard(self, new_shard: Shard) -> None:
        self.shards.append(new_shard)

    def store_data(self, data: Data) -> None:
        pass  # This method is not implemented in the Java code. I've left it as a placeholder.


class RangeShardManager(LookupShardManager):
    pass


class HashShardManager(LookupShardManager):
    pass


def main():
    data1 = Data(1, "data1", "TYPE_1")
    data2 = Data(2, "data2", "TYPE_2")
    data3 = Data(3, "data3", "TYPE_3")
    data4 = Data(4, "data4", "TYPE_1")

    shard1 = Shard(1)
    shard2 = Shard(2)
    shard3 = Shard(3)

    lookup_shard_manager = LookupShardManager()
    lookup_shard_manager.add_new_shard(shard1)
    lookup_shard_manager.add_new_shard(shard2)
    lookup_shard_manager.add_new_shard(shard3)
    lookup_shard_manager.store_data(data1)
    lookup_shard_manager.store_data(data2)
    lookup_shard_manager.store_data(data3)
    lookup_shard_manager.store_data(data4)

    shard1.clear_data()
    shard2.clear_data()
    shard3.clear_data()

    range_shard_manager = RangeShardManager()
    range_shard_manager.add_new_shard(shard1)
    range_shard_manager.add_new_shard(shard2)
    range_shard_manager.add_new_shard(shard3)
    range_shard_manager.store_data(data1)
    range_shard_manager.store_data(data2)
    range_shard_manager.store_data(data3)
    range_shard_manager.store_data(data4)

    shard1.clear_data()
    shard2.clear_data()
    shard3.clear_data()

    hash_shard_manager = HashShardManager()
    hash_shard_manager.add_new_shard(shard1)
    hash_shard_manager.add_new_shard(shard2)
    hash_shard_manager.add_new_shard(shard3)
    hash_shard_manager.store_data(data1)
    hash_shard_manager.store_data(data2)
    hash_shard_manager.store_data(data3)
    hash_shard_manager.store_data(data4)

    shard1.clear_data()
    shard2.clear_data()
    shard3.clear_data()


if __name__ == "__main__":
    main()

