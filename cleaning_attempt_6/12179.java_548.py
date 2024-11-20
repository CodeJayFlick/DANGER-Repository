class CodeBlockImpl:
    def __init__(self, model, starts, set):
        if starts is not None:
            self.starts = starts.copy()
            self.starts.sort()  # store start Addresses in natural sorted order
        self.model = model
        self.set = set

    def get_first_start_address(self):
        return self.starts[0]

    def get_start_addresses(self):
        return self.starts

    def get_name(self):
        return self.model.get_name(self)

    def get_flow_type(self):
        return self.model.get_flow_type(self)

    def get_num_sources(self, monitor):
        try:
            return self.model.get_num_sources(self, monitor)
        except CancelledException as e:
            print(f"Unexpected Exception: {e.message}")

    def get_sources(self, monitor):
        try:
            return self.model.get_sources(self, monitor)
        except CancelledException as e:
            print(f"Unexpected Exception: {e.message}")

    def get_num_destinations(self, monitor):
        try:
            return self.model.get_num_destinations(self, monitor)
        except CancelledException as e:
            print(f"Unexpected Exception: {e.message}")

    def get_destinations(self, monitor):
        try:
            return self.model.get_destinations(self, monitor)
        except CancelledException as e:
            print(f"Unexpected Exception: {e.message}")

    def get_model(self):
        return self.model

    def __str__(self):
        s_list = []
        d_list = []

        try:
            for ref in self.get_sources(TaskMonitorAdapter.DUMMY_MONITOR):
                a = ref.source_address
                s_list.append(a)
            for ref in self.get_destinations(TaskMonitorAdapter.DUMMY_MONITOR):
                a = ref.destination_address
                d_list.append(a)
        except CancelledException as e:
            print(f"Unexpected Exception: {e.message}")

        return f"{self.model.get_name(self)} src:{s_list} dst:{d_list}"

    def contains(self, address):
        return self.set.contains(address)

    def contains(self, start, end):
        return self.set.contains(start, end)

    def contains(self, addr_set):
        return self.set.contains(addr_set)

    def intersects(self, start, end):
        return self.set.intersects(start, end)

    def intersects(self, addr_set):
        return self.set.intersects(addr_set)

    def intersect(self, view):
        return self.set.intersect(view)

    def intersect_range(self, start, end):
        return self.set.intersect_range(start, end)

    def union(self, addr_set):
        return self.set.union(addr_set)

    def xor(self, addr_set):
        return self.set.xor(addr_set)

    def subtract(self, addr_set):
        return self.set.subtract(addr_set)

    def is_empty(self):
        return self.set.is_empty()

    def get_min_address(self):
        return self.set.get_min_address()

    def get_max_address(self):
        return self.set.get_max_address()

    def get_num_address_ranges(self):
        return self.set.get_num_address_ranges()

    def get_address_ranges(self, start_at_front=False):
        return self.set.get_address_ranges(start_at_front)

    def __eq__(self, obj):
        if not isinstance(obj, CodeBlockImpl):
            return False

        if self.model.name != obj.model.name:
            return False
        for i in range(len(self.starts)):
            if self.starts[i] != obj.starts[i]:
                return False
        return True

    def __hash__(self):
        return hash(self.starts[0])

    def get_first_range(self):
        return self.set.get_first_range()

    def get_last_range(self):
        return self.set.get_last_range()

    def get_range_containing(self, address):
        return self.set.get_range_containing(address)

    def iterator(self, forward=True):
        return self.set.iterator(forward)

    def iterator(self, start, forward=True):
        return self.set.iterator(start, forward)

    def find_first_address_in_common(self, other_set):
        return self.set.find_first_address_in_common(other_set)
