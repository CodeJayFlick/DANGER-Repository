class SettlePlan:
    def __init__(self, sg_path=None, ts_file_path=None):
        super().__init__(False, "SETTLE")
        self.sg_path = sg_path
        self.ts_file_path = ts_file_path
        if sg_path is not None and ts_file_path is None:
            self.is_sg_path = True
        elif sg_path is None and ts_file_path is not None:
            self.is_sg_path = False

    @property
    def is_sg_path(self):
        return self._is_sg_path

    @is_sg_path.setter
    def is_sg_path(self, value):
        self._is_sg_path = value

    def get_paths(self):
        if self.sg_path is not None:
            return [self.sg_path]
        else:
            return []

    @property
    def sg_path(self):
        return self._sg_path

    @sg_path.setter
    def sg_path(self, value):
        self._sg_path = value

    @property
    def ts_file_path(self):
        return self._ts_file_path

    @ts_file_path.setter
    def ts_file_path(self, value):
        self._ts_file_path = value
