class UserAddedSourceInfo:
    def __init__(self, fsrl):
        self.fsrl = fsrl
        self.file_count = 0
        self.raw_file_count = 0
        self.container_count = 0
        self.max_nest_level = 0
        self.recurse_terminated_early = False

    @property
    def file_count(self):
        return self._file_count

    @file_count.setter
    def file_count(self, value):
        self._file_count = value

    @property
    def raw_file_count(self):
        return self._raw_file_count

    @raw_file_count.setter
    def raw_file_count(self, value):
        self._raw_file_count = value

    def inc_raw_file_count(self):
        self.raw_file_count += 1

    @property
    def container_count(self):
        return self._container_count

    @container_count.setter
    def container_count(self, value):
        self._container_count = value

    def inc_container_count(self):
        self.container_count += 1

    @property
    def max_nest_level(self):
        return self._max_nest_level

    @max_nest_level.setter
    def max_nest_level(self, value):
        self._max_nest_level = value

    @property
    def recurse_terminated_early(self):
        return self._recurse_terminated_early

    @recurse_terminated_early.setter
    def recurse_terminated_early(self, value):
        self._recurse_terminated_early = value

    @property
    def fsrl(self):
        return self._fsrl

    @fsrl.setter
    def fsrl(self, value):
        self._fsrl = value
