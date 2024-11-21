import unittest
from datetime import timedelta

class ClusterQueryRouterTest(unittest.TestCase):

    def setUp(self):
        self.cluster_query_router = None

    @unittest.skip("This test case needs to be implemented")
    def test_raw_data_query(self):
        query_plan = RawDataQueryPlan()
        path_list = []
        data_types = []

        # implement the rest of this method
        pass

    @unittest.skip("This test case needs to be implemented")
    def test_aggregation(self):
        plan = AggregationPlan()
        paths = [PartialPath(0, 0), PartialPath(0, 1), PartialPath(0, 2), PartialPath(0, 3), PartialPath(0, 4)]
        data_types = [TSDataType.DOUBLE] * len(paths)
        aggregations = ['MIN_TIME', 'MAX_VALUE', 'AVG', 'COUNT', 'SUM']

        plan.set_paths(paths)
        plan.set_deduplicated_paths(path_list)
        plan.set_data_types(data_types)
        plan.set_deduplicated_data_types(data_types)
        plan.set_aggregations(aggregations)
        plan.set_deduplicated_aggregations(aggregations)

        context = QueryContext()
        try:
            query_dataset = self.cluster_query_router.aggregate(plan, context)
            # implement the rest of this method
            pass
        finally:
            end_query(context.get_query_id())

    @unittest.skip("This test case needs to be implemented")
    def test_previous_fill(self):
        plan = FillQueryPlan()
        path_list = [PartialPath(0, 10)]
        data_types = [TSDataType.DOUBLE]

        default_fill_interval = IoTDBDescriptor.getInstance().getConfig().getDefaultFillInterval()

        ts_data_type_ifill_map = {TSDataType.DOUBLE: PreviousFill(TSDataType.DOUBLE, 0, default_fill_interval)}

        plan.set_deduplicated_paths(path_list)
        plan.set_paths(plan.get_deduplicated_paths())
        plan.set_data_types(data_types)
        plan.set_fill_type(ts_data_type_ifill_map)

        context = QueryContext()
        try:
            query_dataset = self.cluster_query_router.fill(plan, context)
            # implement the rest of this method
            pass
        finally:
            end_query(context.get_query_id())

    @unittest.skip("This test case needs to be implemented")
    def test_linear_fill(self):
        plan = FillQueryPlan()
        path_list = [PartialPath(0, 10)]
        data_types = [TSDataType.DOUBLE]

        default_fill_interval = IoTDBDescriptor.getInstance().getConfig().getDefaultFillInterval()

        ts_data_type_ifill_map = {TSDataType.DOUBLE: LinearFill(TSDataType.DOUBLE, 0, default_fill_interval)}

        plan.set_deduplicated_paths(path_list)
        plan.set_paths(plan.get_deduplicated_paths())
        plan.set_data_types(data_types)
        plan.set_fill_type(ts_data_type_ifill_map)

        context = QueryContext()
        try:
            query_dataset = self.cluster_query_router.fill(plan, context)
            # implement the rest of this method
            pass
        finally:
            end_query(context.get_query_id())

    @unittest.skip("This test case needs to be implemented")
    def test_v_filter_group_by(self):
        query_context = QueryContext()
        try:
            group_by_plan = GroupByTimePlan()
            path_list = [PartialPath(0, 0) for _ in range(10)]
            data_types = [TSDataType.DOUBLE] * len(path_list)
            aggregations = ['COUNT'] * len(path_list)

            group_by_plan.set_paths(path_list)
            group_by_plan.set_deduplicated_paths(path_list)
            group_by_plan.set_data_types(data_types)
            group_by_plan.set_aggregations(aggregations)

            query_dataset = self.cluster_query_router.group_by(group_by_plan, query_context)
            # implement the rest of this method
            pass
        finally:
            end_query(query_context.get_query_id())

    @unittest.skip("This test case needs to be implemented")
    def test_no_v_filter_group_by(self):
        query_context = QueryContext()
        try:
            group_by_plan = GroupByTimePlan()
            path_list = [PartialPath(0, 0) for _ in range(10)]
            data_types = [TSDataType.DOUBLE] * len(path_list)
            aggregations = ['COUNT'] * len(path_list)

            group_by_plan.set_paths(path_list)
            group_by_plan.set_deduplicated_paths(path_list)
            group_by_plan.set_data_types(data_types)
            group_by_plan.set_aggregations(aggregations)

            query_dataset = self.cluster_query_router.group_by(group_by_plan, query_context)
            # implement the rest of this method
            pass
        finally:
            end_query(query_context.get_query_id())

    @unittest.skip("This test case needs to be implemented")
    def test_udtf_query(self):
        processor = ClusterPlanner()
        sql_str = "select sin(s0) from root.*"
        plan = processor.parse_sql_to_physical_plan(sql_str)
        udtf_plan = UDTFPlan(plan)

        context = QueryContext()
        try:
            query_dataset = self.cluster_query_router.udtf_query(udtf_plan, context)
            # implement the rest of this method
            pass
        finally:
            end_query(context.get_query_id())

if __name__ == '__main__':
    unittest.main()
