class IQueryRouter:
    def __init__(self):
        pass

    def rawData_query(self, query_plan: 'RawDataQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("raw_data_query not implemented")

    def aggregate(self, aggregation_plan: 'AggregationPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("aggregate not implemented")

    def group_by(self, group_by_time_plan: 'GroupByTimePlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("group_by not implemented")

    def fill(self, fill_query_plan: 'FillQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("fill not implemented")

    def group_by_fill(self, group_by_fill_plan: 'GroupByTimeFillPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("group_by_fill not implemented")

    def last_query(self, last_query_plan: 'LastQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("last_query not implemented")

    def udtf_query(self, udtf_plan: 'UDTFPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("udtf_query not implemented")
