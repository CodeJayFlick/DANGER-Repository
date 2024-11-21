class ShardManagerTest:
    def __init__(self):
        self.shard_manager = TestShardManager()

    @classmethod
    def setUpClass(cls):
        cls.shard_manager = TestShardManager()

    def test_add_new_shard(self):
        shard = {"id": 1}
        self.shard_manager.add_new_shard(shard)
        self.assertEqual(len(self.shard_manager.shard_map), 1)
        self.assertEqual(list(self.shard_manager.shard_map.keys())[0], 1)

    def test_remove_shard_by_id(self):
        shard = {"id": 1}
        self.shard_manager.add_new_shard(shard)
        flag = self.shard_manager.remove_shard_by_id(1)
        self.assertTrue(flag)
        self.assertEqual(len(self.shard_manager.shard_map), 0)

    def test_get_shard_by_id(self):
        shard = {"id": 1}
        self.shard_manager.add_new_shard(shard)
        tmp_shard = self.shard_manager.get_shard_by_id(1)
        self.assertEqual(tmp_shard, shard)


class TestShardManager:
    def __init__(self):
        self.shard_map = {}

    def add_new_shard(self, shard):
        self.shard_map[shard["id"]] = shard

    def remove_shard_by_id(self, id):
        if id in self.shard_map:
            del self.shard_map[id]
            return True
        else:
            return False

    def get_shard_by_id(self, id):
        return self.shard_map.get(id)
