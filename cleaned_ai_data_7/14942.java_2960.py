class RangeShardManager:
    def __init__(self):
        self.shards = []

    def add_new_shard(self, shard):
        self.shards.append(shard)

    def store_data(self, data):
        for i in range(len(self.shards)):
            if 1 <= int(data.id) % (i + 2) < len(self.shards) + 1:
                return self.shards[i].store_data(data)
        raise Exception("No shard found to store the data")

    def get_shard_by_id(self, id):
        for i in range(len(self.shards)):
            if int(id) % (i + 2) == 0:
                return self.shards[i]
        raise Exception("Shard not found")


class Shard:
    def __init__(self, id):
        self.id = id
        self.data_storage = {}

    def store_data(self, data):
        self.data_storage[data.id] = data


import unittest

class TestRangeShardManager(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.range_shard_manager = RangeShardManager()
        for i in range(3):
            cls.range_shard_manager.add_new_shard(Shard(i))

    def test_store_data(self):
        data = Data(1, "test", 0)
        self.range_shard_manager.store_data(data)
        self.assertEqual(data, self.range_shard_manager.get_shard_by_id("1").data_storage["1"])


class Data:
    def __init__(self, id, value, type_):
        self.id = str(id)
        self.value = value
        self.type = type_

if __name__ == '__main__':
    unittest.main()
