import logging
from typing import List, Tuple

class ClusterLastQueryExecutor:
    def __init__(self, last_query_plan: 'RawDataQueryPlan', meta_group_member: 'MetaGroupMember'):
        self.meta_group_member = meta_group_member
        super().__init__(last_query_plan)

    @staticmethod
    def get_logger():
        return logging.getLogger(ClusterLastQueryExecutor.__name__)

    def calculate_last_pair_for_series(self, series_paths: List['PartialPath'], data_types: List[int], context: 'QueryContext', expression: 'IExpression', last_query_plan: 'RawDataQueryPlan') -> Tuple[bool, int]:
        # ...
