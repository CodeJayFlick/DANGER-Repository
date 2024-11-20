Here is the equivalent Python code:

```Python
import unittest
from io import BytesIO, StringIO
try:
    from typing import List
except ImportError:
    pass  # Not necessary for this test case.

class PullSnapshotTaskDescriptorTest(unittest.TestCase):

    def test_serialize(self):
        group = []
        slots = []

        for i in range(10):
            group.append(i)
            slots.append(i)

        descriptor = {'group': group, 'slots': slots, 'is_leader': True}

        bytes_io = BytesIO()
        import pickle
        pickle.dump(descriptor, bytes_io)
        bytes = bytes_io.getvalue()

        bytes_io = BytesIO(bytes)
        deserialized = pickle.load(bytes_io)

        self.assertEqual(descriptor, deserialized)


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalents for Java's `PartitionGroup`, `DataInputStream` and `DataOutputStream`. Instead, we use a dictionary to represent the data structure. The serialization is done using the built-in `pickle` module in Python.