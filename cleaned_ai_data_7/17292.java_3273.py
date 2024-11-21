class InsertMultiTabletPlan:
    def __init__(self):
        self.insert_tablet_plan_list = []
        self.parent_insert_tablet_plan_index_list = []

    def add_insert_tablet_plan(self, plan, parent_index):
        self.insert_tablet_plan_list.append(plan)
        self.parent_insert_tablet_plan_index_list.append(parent_index)

    @property
    def insert_tablet_plan_list(self):
        return self._insert_tablet_plan_list

    @insert_tablet_plan_list.setter
    def insert_tablet_plan_list(self, value):
        self._insert_tablet_plan_list = value

    @property
    def parent_insert_tablet_plan_index_list(self):
        return self._parent_insert_tablet_plan_index_list

    @parent_insert_tablet_plan_index_list.setter
    def parent_insert_tablet_plan_index_list(self, value):
        self._parent_insert_tablet_plan_index_list = value

    def get_paths(self):
        result = []
        for plan in self.insert_tablet_plan_list:
            result.extend(plan.get_paths())
        return result

    def get_prefix_paths(self):
        if not hasattr(self, 'prefix_paths'):
            self.prefix_paths = [plan.get_prefix_path() for plan in self.insert_tablet_plan_list]
        return self.prefix_paths

    @property
    def results(self):
        return self._results

    @results.setter
    def results(self, value):
        self._results = value

    def get_min_time(self):
        min_time = float('inf')
        for plan in self.insert_tablet_plan_list:
            if plan.get_min_time() < min_time:
                min_time = plan.get_min_time()
        return min_time

    def get_max_time(self):
        max_time = -float('inf')
        for plan in self.insert_tablet_plan_list:
            if plan.get_max_time() > max_time:
                max_time = plan.get_max_time()
        return max_time

    @property
    def total_row_count(self):
        count = 0
        for plan in self.insert_tablet_plan_list:
            count += plan.get_row_count()
        return count

    def get_row_count(self, index):
        if index >= len(self.insert_tablet_plan_list) or index < 0:
            return 0
        return self.insert_tablet_plan_list[index].get_row_count()

    @property
    def first_device_id(self):
        return self.insert_tablet_plan_list[0].get_prefix_path() if self.insert_tablet_plan_list else None

    def get_insert_tablet_plan(self, index):
        if index >= len(self.insert_tablet_plan_list) or index < 0:
            return None
        return self.insert_tablet_plan_list[index]

    @property
    def parent_index(self, index):
        if index >= len(self.parent_insert_tablet_plan_index_list) or index < 0:
            return -1
        return self.parent_insert_tablet_plan_index_list[index]

    def check_integrity(self):
        if not self.insert_tablet_plan_list:
            raise QueryProcessException("sub tablet is empty.")
        for plan in self.insert_tablet_plan_list:
            plan.check_integrity()

    @property
    def parent_insert_tablet_plan_index_list(self):
        return self._parent_insert_tablet_plan_index_list

    @parent_insert_tablet_plan_index_list.setter
    def parent_insert_tablet_plan_index_list(self, value):
        self._parent_insert_tablet_plan_index_list = value

    @property
    def insert_tablet_plan_list(self):
        return self._insert_tablet_plan_list

    @insert_tablet_plan_list.setter
    def insert_tablet_plan_list(self, value):
        self._insert_tablet_plan_list = value

    def get_failing_status(self):
        return StatusUtils.get_failing_status(self.results, len(self.insert_tablet_plan_list))

    def set_results(self, results):
        self._results = results

    @property
    def is_executed(self):
        if not hasattr(self, '_is_executed'):
            self._is_executed = [False] * get_batch_size()
        return self._is_executed

    @is_executed.setter
    def is_executed(self, value):
        if not hasattr(self, '_is_executed'):
            self._is_executed = [False] * get_batch_size()
        self._is_executed[value] = True

    def unset_is_executed(self, i):
        if not hasattr(self, '_is_executed'):
            self._is_executed = [False] * get_batch_size()
        self._is_executed[i] = False
        if self.parent_insert_tablet_plan_index_list and len(self.parent_insert_tablet_plan_index_list) > 0:
            self.results.pop(self.parent_index(i))
        else:
            self.results.pop(i)

    @property
    def is_executed_(self, i):
        if not hasattr(self, '_is_executed'):
            self._is_executed = [False] * get_batch_size()
        return self._is_executed[i]

    @staticmethod
    def get_batch_size():
        return len(get_insert_tablet_plan_list())

def get_insert_tablet_plan_list():
    # TO DO: implement this function to retrieve the list of InsertTabletPlan objects.
    pass

class QueryProcessException(Exception):
    pass

class StatusUtils:
    @staticmethod
    def get_failing_status(results, size):
        failing_status = []
        for i in range(size):
            if results.get(i) is not None and results[i].status == TSStatus.FAILED:
                failing_status.append(TSStatus.FAILED)
            else:
                failing_status.append(TSStatus.SUCCESS)
        return failing_status

class PartialPath:
    pass

class InsertTabletPlan:
    def __init__(self):
        self.min_time = float('inf')
        self.max_time = -float('inf')

    @property
    def min_time(self):
        return self._min_time

    @min_time.setter
    def min_time(self, value):
        self._min_time = value

    @property
    def max_time(self):
        return self._max_time

    @max_time.setter
    def max_time(self, value):
        self._max_time = value

    # TO DO: implement the rest of the methods for InsertTabletPlan class.
