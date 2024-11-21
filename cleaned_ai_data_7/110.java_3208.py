class MemviewMapModel:
    NAME = 0
    ASTART = 1
    ASTOP = 2
    TSTART = 3
    TSTOP = 4

    COLUMN_NAMES = [f"{NAME_}: Name", f"Start Address: {ASTART}", f"End Address: {ASTOP}", f"Start Time: {TSTART}", f"End Time: {TSTOP}"]

    def __init__(self, provider):
        self.provider = provider
        self.mem_list = []
        self.mem_map = {}

    @property
    def mem_boxes(self):
        return self.mem_list

    def add_boxes(self, boxes):
        if not self.mem_list:
            self.mem_list = []
            self.mem_map = {}
        for box in boxes:
            if box.id() in self.mem_map:
                old_box = self.mem_map[box.id()]
                self.mem_list.remove(old_box)
            self.mem_list.append(box)
            self.mem_map[box.id()] = box
        self.fire_table_data_changed()

    def set_boxes(self, boxes):
        self.mem_list = []
        for box in boxes:
            self.mem_list.append(box)
            self.mem_map[box.id()] = box
        self.fire_table_data_changed()

    def reset(self):
        self.mem_list = []
        self.mem_map.clear()
        self.fire_table_data_changed()

    def update(self):
        pass

    def is_sortable(self, column_index):
        return True

    @property
    def name(self):
        return "Memory vs Time Map"

    @property
    def column_count(self):
        return len(self.COLUMN_NAMES)

    def get_column_name(self, column_index):
        if 0 <= column_index < self.column_count:
            return self.COLUMN_NAMES[column_index]
        else:
            return "Unknown"

    def find_column(self, column_name):
        for i in range(len(self.COLUMN_NAMES)):
            if self.COLUMN_NAMES[i] == column_name:
                return i
        return 0

    @property
    def column_class(self, column_index):
        if column_index in [self.ASTART, self.ASTOP]:
            return type("Address", (), {})
        else:
            return str

    def is_cell_editable(self, row_index, column_index):
        return False

    @property
    def row_count(self):
        return len(self.mem_list)

    def get_box_at(self, row_index):
        if not self.mem_list or 0 > row_index >= len(self.mem_list):
            return None
        box = self.mem_list[row_index]
        try:
            box.get_start()
        except ConcurrentModificationException as e:
            self.update()
        return self.mem_list[row_index]

    def get_index_for_box(self, box):
        return self.mem_list.index(box)

    @property
    def column_value_at_row(self, row_index, column_index):
        if 0 > row_index >= len(self.mem_list) or not isinstance(column_index, int):
            return None
        try:
            switcher = {
                self.NAME: lambda box: box.id(),
                self.ASTART: lambda box: box.get_range().get_min_address(),
                self.ASTOP: lambda box: box.get_range().get_max_address(),
                self.TSTART: lambda box: str(box.get_start()),
                self.TSTOP: lambda box: str(box.get_stop())
            }
            return switcher.get(column_index, lambda x: "Unknown")(self.mem_list[row_index])
        except ConcurrentModificationException as e:
            self.update()
        return None

    @property
    def model_data(self):
        return self.mem_list

    def create_sort_comparator(self, column_index):
        return MemoryMapComparator(column_index)


class MemoryBox:
    pass


class MemoryMapComparator:
    def __init__(self, sort_column):
        self.sort_column = sort_column

    @property
    def sort_column(self):
        return self.sort_column

    def compare(self, b1, b2):
        switcher = {
            MemviewMapModel.NAME: lambda box1, box2: box1.id().casefold() > box2.id().casefold(),
            MemviewMapModel.ASTART: lambda box1, box2: int(box1.get_start_address()) - int(box2.get_start_address()),
            MemviewMapModel.ASTOP: lambda box1, box2: int(box1.get_stop_address()) - int(box2.get_stop_address()),
            MemviewMapModel.TSTART: lambda box1, box2: int(box1.get_start_time()) - int(box2.get_start_time()),
            MemviewMapModel.TSTOP: lambda box1, box2: int(box1.get_stop_time()) - int(box2.get_stop_time())
        }
        return switcher.get(self.sort_column)(b1, b2)
