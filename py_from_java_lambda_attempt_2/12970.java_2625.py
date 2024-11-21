Here is the equivalent Python code:

```Python
class EnumValuePartitionerTest:
    def test_disjoint_values(self):
        values = [1, 2, 4, 8]
        expected_result = [(0x00000001,), (0x00000002,), (0x00000004,), (0x00000008,)]
        self.assertEqual(len(expected_result), len(partition(values)))
        
    def test_all_overlapping_values(self):
        values = [1, 2, 4, 8, 15]
        expected_result = [(0xF000F, {1L, 2L, 4L, 8L, 15L}), ]
        self.assertEqual(len(expected_result), len(partition(values)))
        
    def test_some_overlapping_values(self):
        values = [1, 2, 4, 8, 6]
        expected_result = [(0x00000001,), (0x00000008,), (0x00000006,), (0x00000000,)]
        self.assertEqual(len(expected_result), len(partition(values)))

def partition(values):
    result = []
    mask = 1
    for value in values:
        while not ((mask & value) > 0):
            if result and result[-1][0] == 0:
                result.append((0, set()))
            mask <<= 1
        result.append(((mask - 1,) | (value,), {value}))
    return result

if __name__ == "__main__":
    test = EnumValuePartitionerTest()
    test.test_disjoint_values()
    test.test_all_overlapping_values()
    test.test_some_overlapping_values()
```

This Python code defines a class `EnumValuePartitionerTest` with three methods that correspond to the Java tests. The `partition` function is used by these tests and it partitions the input values into disjoint bit groups based on their binary representation.

The `if __name__ == "__main__":` block at the end of the code runs all the test methods when this script is executed as a standalone program.