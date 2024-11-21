Here is the equivalent Python code:

```Python
import os
from unittest import TestCase


class ChunkLoaderTest(TestCase):

    FILE_PATH = 'outputDataFile'

    def setUp(self):
        TsFileGeneratorForTest.generate_file(1000000, 1024 * 1024, 10000)

    def tearDown(self):
        file_reader.close()
        TsFileGeneratorForTest.after()

    def test(self):
        file_reader = TsFileSequenceReader(FILE_PATH)
        metadata_querier_by_file = MetadataQuerierByFileImpl(file_reader)
        chunk_metadata_list = metadata_querier_by_file.get_chunk_meta_data_list(Path('d2', 's1'))

        series_chunk_loader = CachedChunkLoaderImpl(file_reader)
        for chunk_metadata in chunk_metadata_list:
            chunk = series_chunk_loader.load_chunk(chunk_metadata)
            chunk_header = chunk.header
            self.assertEqual(chunk_header.data_size, len(chunk.data))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@After`. Instead, we use the `setUp()` method to perform any setup operations before each test is run. Similarly, the `tearDown()` method can be used for any cleanup after a test has been run.

Also, in Python, you don't need to explicitly close file handlers like Java's `close()`, as they are automatically closed when the program exits or the handler goes out of scope.

Lastly, Python does not have direct equivalent of JUnit. Instead, we use built-in testing framework called unittest.