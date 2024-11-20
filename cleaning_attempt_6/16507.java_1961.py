import logging
from typing import List, Set

class ClusterAggregator:
    def __init__(self, meta_group_member: 'MetaGroupMember'):
        self.meta_group_member = meta_group_member
        self.logger = logging.getLogger(__name__)

    def get_aggregate_result(self,
                              path: str,
                              device_measurements: Set[str],
                              aggregations: List[str],
                              data_type: int,
                              time_filter: 'Filter',
                              context: 'QueryContext',
                              ascending: bool) -> List['AggregateResult']:
        try:
            self.meta_group_member.sync_leader_with_consistency_check(False)
        except CheckConsistencyException as e:
            raise StorageEngineException(e)

        partition_groups = []
        try:
            partition_groups = self.meta_group_member.route_filter(time_filter, path)
        except EmptyIntervalException as e:
            logging.info(str(e))
            partition_groups = []

        if not partition_groups:
            return []

        results = None
        for partition_group in partition_groups:
            group_result = self.get_aggregate_result(
                path,
                device_measurements,
                aggregations,
                data_type,
                time_filter,
                partition_group,
                context,
                ascending)
            if results is None:
                results = group_result
            else:
                for i, result in enumerate(results):
                    results[i].merge(group_result[i])

        return results

    def get_aggregate_result(self,
                              path: str,
                              device_measurements: Set[str],
                              aggregations: List[str],
                              data_type: int,
                              time_filter: 'Filter',
                              partition_group: 'PartitionGroup',
                              context: 'QueryContext',
                              ascending: bool) -> List['AggregateResult']:
        if not self.meta_group_member.contains_this_node(partition_group):
            return self.get_remote_aggregate_result(
                path,
                device_measurements,
                aggregations,
                data_type,
                time_filter,
                partition_group,
                context,
                ascending)

        local_query_executor = LocalQueryExecutor(self.meta_group_member)
        try:
            results = local_query_executor.get_aggr_result(aggregations, device_measurements, data_type, path, time_filter, context, ascending)
            return results
        except (IOException, QueryProcessException) as e:
            raise StorageEngineException(e)

    def get_remote_aggregate_result(self,
                                    node: 'Node',
                                    request: dict) -> List[bytes]:
        try:
            result_buffers = self.meta_group_member.get_client_provider().get_async_data_client(node).get_aggr_result(request)
            return [result_buffer.tobytes() for result_buffer in result_buffers]
        except (TException, IOException, InterruptedException) as e:
            logging.error(f"Cannot query aggregation {path} from {node}: {e}")
            raise StorageEngineException(RequestTimeOutException("Query aggregate: " + path))

class MetaGroupMember:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def sync_leader_with_consistency_check(self, force_sync: bool) -> None:
        # implementation omitted

    def route_filter(self, time_filter: 'Filter', path: str) -> List['PartitionGroup']:
        # implementation omitted

    def contains_this_node(self, partition_group: 'PartitionGroup') -> bool:
        # implementation omitted
