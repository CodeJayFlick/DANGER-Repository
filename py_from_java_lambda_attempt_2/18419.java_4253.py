Here is the translation of the Java code into Python:

```Python
import os
from datetime import datetime as dt

class ReadInPartitionTest:
    FILE_PATH = 'outputDataFile'
    roTsFile = None
    d1s6timeRangeList = []
    d2s1timeRangeList = []
    d1chunkGroupMetaDataOffsetList = []

    def before(self):
        os.system('generate_file 10000 1024 100')
        reader = TsFileSequenceReader(FILE_PATH)
        self.roTsFile = ReadOnlyTsFile(reader)

        for chunkMetadata in reader.getChunkMetadataList(Path("d1", "s6")):
            d1s6timeRangeList.append(TimeRange(chunkMetadata.getStartTime(), chunkMetadata.getEndTime()))
            startEndOffsets = [chunkMetadata.getOffsetOfChunkHeader()]
            startEndOffsets[0] += len(chunkMetadata.getMeasurementUid().getBytes()) + 8 + 2
            self.d1chunkGroupMetaDataOffsetList.append(startEndOffsets)

        for chunkMetadata in reader.getChunkMetadataList(Path("d2", "s1")):
            d2s1timeRangeList.append(TimeRange(chunkMetadata.getStartTime(), chunkMetadata.getEndTime()))

    def after(self):
        if self.roTsFile is not None:
            self.roTsFile.close()
        os.system('after')

    def test0(self):
        paths = [Path("d1", "s6"), Path("d2", "s1")]
        queryExpression = QueryExpression.create(paths, None)

        queryDataSet = self.roTsFile.query(queryExpression, 0L, 0L)
        
        assert not queryExpression.getExpression()
        assert not queryDataSet.hasNext()

    def test1(self):
        paths = [Path("d1", "s6"), Path("d2", "s1")]
        queryExpression = QueryExpression.create(paths, None)

        queryDataSet = self.roTsFile.query(queryExpression, 
                                            d1chunkGroupMetaDataOffsetList[0][0], 
                                            d1chunkGroupMetaDataOffsetList[0][1])
        
        transformedExpression = queryExpression.getExpression()
        assert isinstance(transformedExpression, GlobalTimeExpression)
        expectedTimeExpression = BinaryExpression.and(d1s6timeRangeList[0].getExpression(), 
                                                       transformedExpression).optimize(queryExpression.getSelectedSeries())
        assert str(expectedTimeExpression) == str(transformedExpression)

        while queryDataSet.hasNext() and self.roTsFile.query(queryExpression).hasNext():
            r, r2 = next(queryDataSet), next(self.roTsFile.query(queryExpression))
            assert str(r) == str(r2)
        
        assert not queryDataSet.hasNext()
        assert not self.roTsFile.query(queryExpression).hasNext()

    def test2(self):
        paths = [Path("d1", "s6"), Path("d2", "s1")]
        expression = GlobalTimeExpression(50L)

        queryExpression = QueryExpression.create(paths, expression)
        
        queryDataSet = self.roTsFile.query(queryExpression, 
                                            d1chunkGroupMetaDataOffsetList[0][0], 
                                            d1chunkGroupMetaDataOffsetList[0][1])
        
        transformedExpression = queryExpression.getExpression()
        assert isinstance(transformedExpression, GlobalTimeExpression)
        expectedTimeExpression = BinaryExpression.and(expression, d1s6timeRangeList[0].getExpression()).optimize(queryExpression.getSelectedSeries())
        assert str(expectedTimeExpression) == str(transformedExpression)

        while queryDataSet.hasNext() and self.roTsFile.query(queryExpression).hasNext():
            r, r2 = next(queryDataSet), next(self.roTsFile.query(queryExpression))
            assert str(r) == str(r2)
        
        assert not queryDataSet.hasNext()
        assert not self.roTsFile.query(queryExpression).hasNext()

    def test3(self):
        paths = [Path("d1", "s6"), Path("d2", "s1")]
        filter = ValueFilter(10L)

        expression = SingleSeriesExpression(Path("d1", "s3"), filter)
        
        queryExpression = QueryExpression.create(paths, expression)
        
        queryDataSet = self.roTsFile.query(queryExpression, 
                                            d1chunkGroupMetaDataOffsetList[0][0], 
                                            d1chunkGroupMetaDataOffsetList[0][1])
        
        transformedExpression = queryExpression.getExpression()
        assert isinstance(transformedExpression, SingleSeriesExpression)
        expectedTimeExpression = BinaryExpression.and(expression, d1s6timeRangeList[0].getExpression()).optimize(queryExpression.getSelectedSeries())
        assert str(expectedTimeExpression) == str(transformedExpression)

        while queryDataSet.hasNext() and self.roTsFile.query(queryExpression).hasNext():
            r, r2 = next(queryDataSet), next(self.roTsFile.query(queryExpression))
            assert str(r) == str(r2)
        
        assert not queryDataSet.hasNext()
        assert not self.roTsFile.query(queryExpression).hasNext()

class Path:
    def __init__(self, series_id, measurement_id):
        pass

class TimeRange:
    def __init__(self, start_time, end_time):
        pass

class GlobalTimeExpression:
    def __init__(self, time_filter):
        self.time_filter = time_filter
        pass

class SingleSeriesExpression:
    def __init__(self, path, filter):
        self.path = path
        self.filter = filter
        pass

class QueryExpression:
    @staticmethod
    def create(paths, expression):
        return None  # This is not implemented in the Java code either.

    def get_expression(self):
        return None  # This is not implemented in the Java code either.

    def optimize(self, selected_series):
        return self  # This is not implemented in the Java code either.

class QueryDataSet:
    def __init__(self):
        pass

    def has_next(self):
        return False  # This is not implemented in the Java code either.

    def next(self):
        return None  # This is not implemented in the Java code either.
```

Note that this translation assumes you have a `TsFileSequenceReader`, `ReadOnlyTsFile`, and other classes similar to those used in the original Java code.