Here is the translation of the Java code to Python:

```Python
import os
from datetime import datetime as dt

class TimeGeneratorTest:
    FILE_PATH = 'outputDataFile'
    start_timestamp = 1480562618000

    def __init__(self):
        self.file_reader = None
        self.metadata_querier_by_file = None
        self.chunk_loader = None

    def before(self):
        os.environ['TIME_ENCODER'] = "TS_2DIFF"
        # generate file logic here, assuming it's a separate function
        self.generate_file(1000, 10 * 1024 * 1024, 10000)
        self.file_reader = TsFileSequenceReader(FILE_PATH)
        self.metadata_querier_by_file = MetadataQuerierByFileImpl(self.file_reader)
        self.chunk_loader = CachedChunkLoaderImpl(self.file_reader)

    def after(self):
        if self.file_reader:
            self.file_reader.close()
        # after logic here, assuming it's a separate function
        TsFileGeneratorForTest.after()

    def test_time_generator(self):
        filter1 = TimeFilter.lt(1480562618100)
        filter2 = ValueFilter.gt(Binary("dog"))
        filter3 = FilterFactory.and(TimeFilter.geq(1480562618000), TimeFilter.leq(1480562618100))

        expression = BinaryExpression.or(
            BinaryExpression.and(
                SingleSeriesExpression(Path("d1", "s1"), filter1),
                SingleSeriesExpression(Path("d1", "s4"), filter2)
            ),
            SingleSeriesExpression(Path("d1", "s1"), filter3)
        )

        timestamp_generator = TsFileTimeGenerator(expression, self.chunk_loader, self.metadata_querier_by_file)

        while timestamp_generator.has_next():
            # System.out.println(timestamp_generator.next());
            assert timestamp_generator.next() == start_timestamp
            start_timestamp += 1

        assert start_timestamp == 1480562618101


class TsFileSequenceReader:
    def __init__(self, file_path):
        self.file_path = file_path

    def close(self):
        pass


class MetadataQuerierByFileImpl:
    def __init__(self, file_reader):
        self.file_reader = file_reader


class CachedChunkLoaderImpl:
    def __init__(self, file_reader):
        self.file_reader = file_reader


class FilterFactory:
    @staticmethod
    def and(*filters):
        pass


class TimeFilter:
    @classmethod
    def lt(cls, timestamp):
        return cls(timestamp)

    @classmethod
    def geq(cls, timestamp):
        return cls(timestamp)


class ValueFilter:
    @classmethod
    def gt(cls, value):
        return cls(value)


class BinaryExpression:
    @staticmethod
    def or(*expressions):
        pass


class SingleSeriesExpression:
    def __init__(self, path, filter=None):
        self.path = path
        self.filter = filter


class TsFileTimeGenerator:
    def __init__(self, expression, chunk_loader, metadata_querier_by_file):
        self.expression = expression
        self.chunk_loader = chunk_loader
        self.metadata_querier_by_file = metadata_querier_by_file

    def has_next(self):
        pass

    def next(self):
        return 0


# Usage:
test = TimeGeneratorTest()
test.before()
try:
    test.test_time_generator()
finally:
    test.after()

```

Please note that the `generate_file` function is not implemented in this code. It's assumed to be a separate function based on your original Java code.