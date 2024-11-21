import unittest
from collections import deque

class FunctionGraphCacheTest(unittest.TestCase):
    def setUp(self):
        self.cache = {}
        self.disposed_function_data = set()
        self.evicted_from_cache = set()

    # partial fake of FGController to take control of the buildCache() method and spy 
    # on the two methods that might dispose a FunctionGrahpData object.
    class FakeFunctionGraphController:
        def __init__(self):
            pass

        @staticmethod
        def build_cache(listener):
            return {}

        @staticmethod
        def dispose_if_not_in_cache(invocation, data):
            if not invocation.proceed(data):
                function = data['function']
                address = function.get_entry_point()
                self.disposed_function_data.add(address)

        @staticmethod
        def dispose_graph_data_if_not_in_use(invocation, data):
            evicted_from_cache.add(data['function'].get_entry_point())

    # testNewFunctionIsCacheMiss
    def test_new_function_is_cache_miss(self):
        for _ in range(2):
            self.cache = {}
            self.go_to_address(function_addrs[0])
            stats1 = self.get_stats()
            self.assertEqual(stats1['miss_count'] + 1, self.get_stats()['miss_count'])

            self.go_to_address(function_addrs[1])
            stats2 = self.get_stats()
            self.assertEqual(stats1['hit_count'], stats2['hit_count'])
            self.assertEqual(stats1['miss_count'] + 1, stats2['miss_count'])

    # testBackToOldFunctionIsCacheHit
    def test_back_to_old_function_is_cache_hit(self):
        for _ in range(3):
            self.go_to_address(function_addrs[0])
            stats1 = self.get_stats()
            self.assertEqual(stats1['hit_count'], 2)
            self.assertEqual(stats1['miss_count'], 0)

            self.go_to_address(function_addrs[1])
            stats2 = self.get_stats()
            self.assertEqual(stats1['hit_count'], 3)
            self.assertEqual(stats1['miss_count'], 0)

    # testCallbackWhenEvicted
    def test_callback_when_evicted(self):
        for _ in range(4):
            self.go_to_address(function_addrs[0])
            stats = self.get_stats()
            self.assertEqual(len(self.evicted_from_cache), 3)
            self.assertEqual(self.disposed_function_data, {function_addrs[0]})

    # testCacheHitDoesntDisposeCurrentFunction
    def test_cache_hit_doesnt_dispose_current_function(self):
        for _ in range(2):
            self.go_to_address(function_addrs[0])
            stats = self.get_stats()
            self.assertEqual(len(self.evicted_from_cache), 1)
            self.assertEqual(self.disposed_function_data, {function_addrs[0]})

    # testForcedEvictionDisposesAllExceptCurrentFunction
    def test_forced_eviction_disposes_all_except_current_function(self):
        for _ in range(3):
            self.go_to_address(function_addrs[0])
            stats = self.get_stats()
            self.assertEqual(len(self.evicted_from_cache), 2)
            self.assertEqual(self.disposed_function_data, {function_addrs[0], function_addrs[1]})

    def go_to_address(self, address):
        pass

    def get_stats(self):
        return {}

if __name__ == '__main__':
    unittest.main()
