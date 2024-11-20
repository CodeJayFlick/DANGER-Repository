class NodeAdditionResult:
    def __init__(self):
        self.new_group_list = []

    @property
    def new_group_list(self):
        return self._new_group_list

    @new_group_list.setter
    def new_group_list(self, value):
        self._new_group_list = value

    def add_new_group(self, new_group):
        self.new_group_list.append(new_group)
