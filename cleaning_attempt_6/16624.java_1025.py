import hashlib
from typing import List, Set

class PartitionUtils:
    def __init__(self):
        pass  # util class

    @staticmethod
    def is_local_non_query_plan(plan: 'PhysicalPlan') -> bool:
        return isinstance(plan, (LoadDataPlan, OperateFilePlan)) or \
               isinstance(plan, LoadConfigurationPlan) and plan.load_configuration_plan_type == LoadConfigurationPlanType.LOCAL

    @staticmethod
    def is_global_meta_plan(plan: 'PhysicalPlan') -> bool:
        return isinstance(plan, (SetStorageGroupPlan, SetTTLPlan, ShowTTLPlan,
                                 LoadConfigurationPlan)) or \
               isinstance(plan, (AuthorPlan, DeleteStorageGroupPlan, DataAuthPlan,
                                 CreateTemplatePlan, CreateFunctionPlan, DropFunctionPlan,
                                 CreateSnapshotPlan, SetSystemModePlan))

    @staticmethod
    def is_global_data_plan(plan: 'PhysicalPlan') -> bool:
        return isinstance(plan, (DeletePlan, DeleteTimeSeriesPlan)) or \
               plan in [MergePlan, FlushPlan] or \
               isinstance(plan, (SetSchemaTemplatePlan, ClearCachePlan))

    @staticmethod
    def calculate_storage_group_slot_by_time(storage_group_name: str, timestamp: int, slot_num: int) -> int:
        partition_num = StorageEngine.get_time_partition(timestamp)
        return PartitionUtils.calculate_storage_group_slot_by_partition(storage_group_name, partition_num, slot_num)

    @staticmethod
    def calculate_storage_group_slot_by_partition(storage_group_name: str, partition_num: int, slot_num: int) -> int:
        hash_value = hashlib.md5(f"{storage_group_name}{partition_num}".encode()).hexdigest()
        return abs(int(hashlib.sha256(hash_value.encode()).hexdigest(), 16)) % slot_num

    @staticmethod
    def copy(plan: 'InsertTabletPlan', times: List[int], values: List[object], bit_maps: List['BitMap']) -> 'InsertTabletPlan':
        new_plan = InsertTabletPlan(plan.prefix_path, plan.measurements)
        new_plan.data_types = plan.data_types
        new_plan.columns = values
        new_plan.bit_maps = bit_maps
        new_plan.times = times
        new_plan.row_count = len(times)
        new_plan.measurement_m_nodes = plan.measurement_m_nodes
        return new_plan

    @staticmethod
    def reordering(plan: 'InsertTabletPlan', status: List['TSStatus'], sub_status: List['TSStatus']) -> None:
        range_ = plan.get_range()
        dest_loc = 0
        for i in range(0, len(range_), 2):
            start = range_[i]
            end = range_[i + 1]
            status[dest_loc:start] = sub_status[:end - start]
            dest_loc += end - start

    @staticmethod
    def get_interval_headers(storage_group_name: str, time_lower_bound: int, time_upper_bound: int, partition_table: 'PartitionTable', result: Set['RaftNode']) -> None:
        partition_interval = StorageEngine.get_time_partition_interval()
        curr_partition_start = time_lower_bound // partition_interval * partition_interval
        while curr_partition_start <= time_upper_bound:
            result.add(partition_table.route_to_header_by_time(storage_group_name, curr_partition_start))
            curr_partition_start += partition_interval

class LoadDataPlan: pass  # util class
class OperateFilePlan: pass  # util class
class LoadConfigurationPlanType: pass  # util class
class InsertTabletPlan:
    def __init__(self, prefix_path: str, measurements: List[str]):
        self.prefix_path = prefix_path
        self.measurements = measurements

    @property
    def data_types(self) -> List[object]:
        return []

    @data_types.setter
    def data_types(self, value: List[object]) -> None:
        pass  # util class

class BitMap: pass  # util class
