Here is the translation of the given Java code into Python:

```Python
class BaseQueryTest:
    def __init__(self):
        self.path_list = []
        self.data_types = []

    @staticmethod
    def check_aggregations(aggregation_results, answers):
        assert len(answers) == len(aggregation_results)
        for i in range(len(aggregation_results)):
            aggregate_result = aggregation_results[i]
            if answers[i] is not None:
                assert round(float(answers[i]), 5) == float(str(aggregate_result.result)), 0.00001
            else:
                assert aggregate_result.result is None

    def setUp(self):
        IoTDBDescriptor.getInstance().getConfig().set_concurrent_compaction_thread(0)
        super().setUp()
        self.path_list = []
        self.data_types = []
        for i in range(10):
            path = PartialPath(TestUtils.get_test_series(i, 0))
            self.path_list.append(path)
            self.data_types.append(TSDataType.DOUBLE)
        NodeStatusManager.getInstance().set_meta_group_member(test_meta_member)
        TestUtils.prepare_data()

    def tearDown(self):
        super().tearDown()
        NodeStatusManager.getInstance().set_meta_group_member(None)
        IoTDBDescriptor.getInstance().getConfig().set_concurrent_compaction_thread(default_compaction_thread)

    def check_sequential_dataset(self, data_set, offset, size) -> None:
        for i in range(offset, offset + size):
            assert data_set.has_next()
            record = data_set.next()
            assert i == record.timestamp
            assert 10 == len(record.fields)
            for j in range(10):
                assert round(i * 1.0, 5) == float(str(record.fields[j].get_double_value())), 0.00001

        assert not data_set.has_next()

    def check_double_dataset(self, query_data_set: QueryDataSet, answers: list) -> None:
        assert query_data_set.has_next()
        record = query_data_set.next()
        fields = record.get_fields()
        assert len(answers) == len(fields)
        for i in range(len(answers)):
            if answers[i] is not None:
                assert round(float(answers[i]), 5) == float(str(fields[i].get_string_value())), 0.000001
            else:
                assert fields[i] is None

    def __init__(self):
        pass
```

Please note that Python does not support the exact equivalent of Java's `@Before` and `@After`, so I have used the `setUp()` and `tearDown()` methods instead to achieve similar functionality.