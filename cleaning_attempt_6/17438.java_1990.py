import logging
from abc import ABCMeta, abstractmethod
from typing import List, Any

class QueryRouter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def rawDataQuery(self, query_plan: 'RawDataQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        pass

    @abstractmethod
    def aggregate(self, aggregation_plan: 'AggregationPlan', context: 'QueryContext') -> 'QueryDataSet':
        pass

    @abstractmethod
    def group_by(self, groupby_time_plan: 'GroupByTimePlan', context: 'QueryContext') -> 'QueryDataSet':
        pass

    @abstractmethod
    def fill(self, fill_query_plan: 'FillQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        pass

    @abstractmethod
    def last_query(self, last_query_plan: 'LastQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        pass

    @abstractmethod
    def udtf_query(self, udtf_plan: 'UDTFPlan', context: 'QueryContext') -> 'QueryDataSet':
        pass


class RawDataQueryExecutor:
    def __init__(self, query_plan):
        self.query_plan = query_plan

    def execute_non_align(self, context) -> Any:
        # Implementation
        pass

    def execute_with_value_filter(self, context) -> Any:
        # Implementation
        pass

    def execute_without_value_filter(self, context) -> Any:
        # Implementation
        pass


class AggregationExecutor:
    def __init__(self, context: 'QueryContext', aggregation_plan):
        self.context = context
        self.aggregation_plan = aggregation_plan

    def execute_with_value_filter(self) -> Any:
        # Implementation
        pass

    def execute_without_value_filter(self) -> Any:
        # Implementation
        pass


class GroupByEngineDataSet:
    def __init__(self, query_context: 'QueryContext', groupby_time_plan):
        self.query_context = query_context
        self.groupby_time_plan = groupby_time_plan


class EmptyDataSet:
    pass


class QueryDataSet:
    pass


# Other classes and functions are similar to the above code.
