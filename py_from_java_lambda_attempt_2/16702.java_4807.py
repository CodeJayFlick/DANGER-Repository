Here is the equivalent Python code:

```Python
import unittest
from iotdb_cluster_query_reader import ClusterReaderFactory, RemoteQueryContext, SeriesRawDataBatchReader
from iotdb_db_engine import StorageEngine
from iotdb_db_exception import StorageEngineException, MetadataException, QueryProcessException
from iotdb_db_metadata import PartialPath

class TestClusterReaderFactory(unittest.TestCase):

    def test_ttl(self):
        try:
            reader_factory = ClusterReaderFactory(test_meta_member)
            context = RemoteQueryContext(QueryResourceManager().assign_query_id(True))

            series_reader = reader_factory.get_series_batch_reader(
                path_list[0],
                set(),
                data_types[0],
                None,
                None,
                context,
                data_group_member_map[TestUtils.get_raft_node(10, 0)],
                True,
                None
            )
            self.assertIsNotNone(series_reader)

            StorageEngine().set_ttl(PartialPath(TestUtils.get_test_sg(0)), 100)
            series_reader = reader_factory.get_series_batch_reader(
                path_list[0],
                set(),
                data_types[0],
                None,
                None,
                context,
                data_group_member_map[TestUtils.get_raft_node(10, 0)],
                True,
                None
            )
            self.assertIsNone(series_reader)
        finally:
            QueryResourceManager().end_query(context.query_id())
            StorageEngine().set_ttl(PartialPath(TestUtils.get_test_sg(0)), float('inf'))

if __name__ == '__main__':
    unittest.main()
```

Please note that this code assumes you have the necessary modules and classes defined in your Python environment. The `iotdb_cluster_query_reader`, `iotdb_db_engine`, `iotdb_db_exception`, and `iotdb_db_metadata` are not standard Python libraries, so they must be imported from a custom module or installed using pip if available.