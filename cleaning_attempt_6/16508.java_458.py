import logging
from typing import List, Set

class ClusterDataQueryExecutor:
    def __init__(self, plan: 'RawDataQueryPlan', meta_group_member: 'MetaGroupMember'):
        self.logger = logging.getLogger(__name__)
        self.meta_group_member = meta_group_member
        self.reader_factory = ClusterReaderFactory(meta_group_member)

    def execute_without_value_filter(self, context: 'QueryContext') -> 'QueryDataSet':
        data_set = self.need_redirect(context, False)
        if data_set is not None:
            return data_set
        try:
            readers_of_selected_series = self.init_mult_series_reader(context)
            return RawQueryDataSetWithoutValueFilter(
                context.get_query_id(),
                plan.get_deduplicated_paths(),
                plan.get_deduplicated_data_types(),
                readers_of_selected_series,
                plan.is_ascending()
            )
        except (InterruptedException, IOException, EmptyIntervalException, QueryProcessException) as e:
            raise StorageEngineException(str(e))

    def init_mult_series_reader(self, context: 'QueryContext') -> List['ManagedSeriesReader']:
        time_filter = None
        if plan.get_expression() is not None:
            time_filter = ((GlobalTimeExpression)(plan.get_expression())).get_filter()
        
        self.meta_group_member.sync_leader_with_consistency_check(False)
        readers_of_selected_series = []
        mult_point_readers = []

        mult_point_readers = reader_factory.get_mult_series_reader(
            plan.get_deduplicated_paths(),
            plan.get_device_to_measurements(),
            plan.get_deduplicated_data_types(),
            time_filter,
            None,
            context,
            plan.is_ascending()
        )

        for i, partial_path in enumerate(plan.get_deduplicated_paths()):
            full_path = partial_path.get_exact_full_path()
            assign_path_managed_merge_reader = AssignPathManagedMergeReader(full_path)
            for mult_point_reader in mult_point_readers:
                if mult_point_reader.get_all_paths().contains(full_path):
                    assign_path_managed_merge_reader.add_reader(mult_point_reader, 0)
            readers_of_selected_series.append(assign_path_managed_merge_reader)

        self.logger.debug("Initialized {} readers for {}".format(len(readers_of_selected_series), plan))
        return readers_of_selected_series

    # ... (rest of the methods are similar) ...
