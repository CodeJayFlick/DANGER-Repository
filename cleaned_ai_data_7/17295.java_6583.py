class InsertRowsOfOneDevicePlan:
    def __init__(self):
        self.prefix_path = None
        self.row_plans = []
        self.row_plan_index_list = []

    def __init__(self, prefix_path: PartialPath, row_plans: list[InsertRowPlan], row_plan_index_list: list[int]):
        self.__init__()
        self.prefix_path = prefix_path
        self.row_plans = row_plans
        self.row_plan_index_list = row_plan_index_list

    def check_integrity(self):
        pass  # TODO implement this method

    @property
    def paths(self) -> list[PartialPath]:
        if not hasattr(self, 'path_set'):
            path_set = set()
            for plan in self.row_plans:
                path_set.update(plan.paths)
            self.path_set = list(path_set)
        return self.path_set

    @property
    def min_time(self) -> int:
        if not hasattr(self, '_min_time') or _min_time is None:
            _min_time = long.MaxValue
            for plan in self.row_plans:
                if _min_time > plan.time:
                    _min_time = plan.time
        return _min_time

    def serialize(self, stream: bytearray):
        type_ = 0  # PhysicalPlanType.BATCH_INSERT_ONE_DEVICE.ordinal()
        stream[0] = type_
        put_string(stream, self.prefix_path.full_path)
        for i in range(len(self.row_plans)):
            plan = self.row_plans[i]
            stream.extend(long_to_bytes(plan.time))
            plan.serialize_measurements_and_values(stream)

    def serialize(self, buffer: bytearray):
        type_ = 0  # PhysicalPlanType.BATCH_INSERT_ONE_DEVICE.ordinal()
        buffer[0] = type_
        put_string(buffer, self.prefix_path.full_path)
        for i in range(len(self.row_plans)):
            plan = self.row_plans[i]
            buffer.extend(long_to_bytes(plan.time))
            plan.serialize_measurements_and_values(buffer)

    def deserialize(self, buffer: bytearray):
        if len(buffer) < 1:
            return
        type_ = buffer[0]
        self.prefix_path = PartialPath(unicode_string_from_buffer(buffer[1:]))

        for i in range(len(self.row_plans)):
            plan = InsertRowPlan()
            plan.set_prefix_path(self.prefix_path)
            plan.time = long.from_bytes(buffer[i * 8:i * 8 + 8], 'big')
            plan.deserialize_measurements_and_values(buffer[i * 8 + 8:])

    def set_index(self, index):
        super().set_index(index)
        for i in range(len(self.row_plans)):
            self.row_plans[i].index = index

    @property
    def results(self) -> dict:
        return {}

    def get_plan_from_failed(self):
        if not hasattr(super(), 'plan_from_failed') or plan_from_failed is None:
            return None
        plans = []
        for i in range(len(self.row_plans)):
            if self.row_plans[i].has_failed_values():
                plans.append((self.row_plans[i]).get_plan_from_failed())
        self.row_plans = list(plans)
        return self

    @property
    def row_plans(self) -> list[InsertRowPlan]:
        return []

    def is_executed(self, i):
        if not hasattr(self, 'is_executed'):
            self.is_executed = [False] * len(self.row_plan_index_list)
        return self.is_executed[i]

    @property
    def results(self) -> dict:
        return {}

    def get_row_plans(self) -> list[InsertRowPlan]:
        return []

    def set_is_executed(self, i):
        if not hasattr(self, 'is_executed'):
            self.is_executed = [False] * len(self.row_plan_index_list)
        self.is_executed[i] = True

    @property
    def row_plan_index_list(self) -> list[int]:
        return []

    def get_results(self) -> dict:
        return {}

    def unset_is_executed(self, i):
        if not hasattr(self, 'is_executed'):
            self.is_executed = [False] * len(self.row_plan_index_list)
        self.is_executed[i] = False
        if i in self.results:
            del self.results[i]

    @property
    def prefix_paths(self) -> list[PartialPath]:
        return []

    @property
    def batch_size(self):
        return 0

    def __eq__(self, other: 'InsertRowsOfOneDevicePlan'):
        if not isinstance(other, InsertRowsOfOneDevicePlan):
            return False
        return (other.row_plan_index_list == self.row_plan_index_list and 
                other.row_plans == self.row_plans and 
                other.results == self.results)

    def __hash__(self) -> int:
        result = 0
        if self.row_plans:
            result += hash(self.row_plans)
        if self.row_plan_index_list:
            result += sum(hash(i) for i in self.row_plan_index_list)
        if self.results:
            result += hash(self.results)
        return result

class PartialPath:
    def __init__(self, full_path):
        self.full_path = full_path
