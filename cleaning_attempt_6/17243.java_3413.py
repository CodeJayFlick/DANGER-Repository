class CreateIndexOperator:
    def __init__(self):
        self.paths = []
        self.props = {}
        self.time = None
        self.index_type = None

    @property
    def paths(self):
        return self._paths

    @paths.setter
    def paths(self, value):
        self._paths = value

    @property
    def props(self):
        return self._props

    @props.setter
    def props(self, value):
        self._props = value

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value

    @property
    def index_type(self):
        return self._index_type

    @index_type.setter
    def index_type(self, value):
        self._index_type = value

    def add_path(self, path):
        self.paths.append(path)

    def get_physical_plan(self, generator):
        if not isinstance(generator, PhysicalGenerator):
            raise QueryProcessException("Invalid physical generator")
        
        return CreateIndexPlan(self(paths), self.props, self.time, self.index_type)
