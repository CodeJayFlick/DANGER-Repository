import unittest
from typing import List, Dict, Any

class ClusterFillExecutorTest(unittest.TestCase):

    def test_previous_fill(self):
        plan = FillQueryPlan()
        paths = [PartialPath(TestUtils.get_test_series(0, 10))]
        data_types = [TSDataType.DOUBLE]
        plan.set_deduplicated_paths_and_update(paths)
        plan.set_deduplicated_data_types(data_types)
        plan.set_paths(plan.get_deduplicated_paths())
        plan.set_data_types(plan.get_deduplicated_data_types())

        default_fill_interval = IoTDBDescriptor().get_instance().get_config().get_default_fill_interval()
        ts_data_type_ifill_map: Dict[TSDataType, Any] = {TSDataType.DOUBLE: PreviousFill(TSDataType.DOUBLE, 0, default_fill_interval)}
        plan.set_fill_type(ts_data_type_ifill_map)

        context = RemoteQueryContext(QueryResourceManager().assign_query_id(True))

        try:
            fill_executor = ClusterFillExecutor(plan, test_meta_member)
            query_dataset = fill_executor.execute(context)
            answers = [[None], [0.0], [0.0], [10.0], [10.0]]
            for i in range(len(query_times)):
                plan.set_query_time(query_times[i])
                check_double_dataset(query_dataset, answers[i])
                self.assertFalse(query_dataset.has_next())
        finally:
            QueryResourceManager().end_query(context.get_query_id())

    def test_linear_fill(self):
        # Same as previous fill

    def test_value_fill(self):
        # Same as previous fill


if __name__ == '__main__':
    unittest.main()
