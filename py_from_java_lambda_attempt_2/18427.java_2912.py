Here is the equivalent Python code:

```Python
import unittest


class BloomFilterTest(unittest.TestCase):

    def test_in(self):
        value1 = "device1.s1"
        value2 = "device1.s2"
        value3 = "device1.s3"

        filter = self.get_empty_bloom_filter(0.05, 3)
        filter.add(value1)
        filter.add(value2)
        filter.add(value3)

        self.assertTrue(filter.contains(value1))
        self.assertTrue(filter.contains(value2))
        self.assertTrue(filter.contains(value3))

        print(self.filter_contains("12iuedyauydua"))
        print(self.filter_contains("device_1.s1"))
        print(self.filter_contains("device1.s_2"))
        print(self.filter_contains("device2.s1"))
        print(self.filter_contains("device3.s2"))
        print(self.filter_contains("device4.s2"))
        print(self.filter_contains("device1.s4"))

    def test_serialize(self):
        value1 = "device1.s1"
        value2 = "device1.s2"
        value3 = "device1.s3"

        filter = self.get_empty_bloom_filter(0.05, 3)
        filter.add(value1)
        filter.add(value2)
        filter.add(value3)

        filter1 = BloomFilter.build_from_bytes(filter.serialize(), filter.size(), filter.hash_function_size())
        self.assertTrue(filter1.contains(value1))
        self.assertTrue(filter1.contains(value2))
        self.assertTrue(filter1.contains(value3))

    def get_empty_bloom_filter(self, fpp, size):
        # Implement your bloom filter logic here
        pass

    def filter_contains(self, value):
        # Implement your bloom filter contains logic here
        return False


if __name__ == '__main__':
    unittest.main()
```

Note that this code does not implement the actual Bloom Filter functionality. It only translates the Java code to Python and provides placeholder methods for `get_empty_bloom_filter` and `filter_contains`. You would need to implement these methods according to your specific requirements.