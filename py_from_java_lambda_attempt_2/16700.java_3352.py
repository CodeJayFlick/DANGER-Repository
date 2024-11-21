Here is the translation of the Java code into Python:

```Python
import unittest


class ClusterQueryManagerTest(unittest.TestCase):

    def setUp(self):
        self.query_manager = ClusterQueryManager()

    def test_context(self):
        query_context1 = self.query_manager.get_query_context(0, 1)
        query_context2 = self.query_manager.get_query_context(0, 1)
        query_context3 = self.query_manager.get_query_context(1, 1)

        self.assertEqual(query_context1, query_context2)
        self.assertNotEqual(query_context2, query_context3)

    def test_register_reader(self):
        class Reader:
            def __init__(self):
                pass

            def hasNextBatch(self):
                return False

            def next_batch(self):
                return None

            def close(self):
                pass

        reader = Reader()
        id = self.query_manager.register_reader(reader)
        self.assertEqual(id, 0)

    def test_register_reader_by_time(self):
        class ReaderByTime:
            def __init__(self):
                pass

            def read(self, timestamp, length):
                return None

        reader_by_time = ReaderByTime()
        id = self.query_manager.register_reader_by_time(reader_by_time)
        self.assertEqual(id, 0)

    def test_register_aggregate_reader(self):
        class AggregateReader:
            def __init__(self):
                pass

            def hasNextFile(self):
                return False

            def can_use_current_file_statistics(self):
                return False

            def current_file_statistics(self):
                return None

            def skip_current_file(self):
                pass

            def hasNextChunk(self):
                return False

            def can_use_current_chunk_statistics(self):
                return False

            def current_chunk_statistics(self):
                return None

            def skip_current_chunk(self):
                pass

            def hasNextPage(self):
                return False

            def can_use_current_page_statistics(self):
                return False

            def current_page_statistics(self):
                return None

            def skip_current_page(self):
                pass

            def next_batch(self):
                return None

        aggregate_reader = AggregateReader()
        id = self.query_manager.register_aggregate_reader(aggregate_reader)
        self.assertEqual(id, 0)

    def test_end_query(self):
        query_context = self.query_manager.get_query_context(0, 1)
        for i in range(10):
            reader = Reader()
            query_context.register_local_reader(self.query_manager.register_reader(reader))

        self.query_manager.end_query(0, 1)
        for i in range(10):
            self.assertIsNone(self.query_manager.get_reader(i))


if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code is written as a unit test using the `unittest` module. The Java code does not have direct equivalent to this, but I've tried my best to translate it into Python.