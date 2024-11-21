class PathPrivilege:
    def __init__(self):
        self.privileges = set()
        self.path = None
        self.reference_cnt = 0

    def __init__(self, path):
        self.path = path
        self.privileges = set()

    @property
    def privileges(self):
        return self._privileges

    @privileges.setter
    def privileges(self, value):
        self._privileges = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

    @property
    def reference_cnt(self):
        return self._reference_cnt

    @reference_cnt.setter
    def reference_cnt(self, value):
        self._reference_cnt = value

    def __eq__(self, other):
        if not isinstance(other, PathPrivilege):
            return False
        return (isinstance(self.privileges, set) and 
                isinstance(other.privileges, set) and 
                self.path == other.path)

    def __hash__(self):
        return hash((frozenset(self.privileges), self.path))

    def __str__(self):
        if not self.path:
            path_str = "null"
        else:
            path_str = str(self.path)
        privilege_strs = [str(PrivilegeType.values()[i]) for i in sorted(list(self.privileges))]
        return f"{path_str}: {', '.join(privilege_strs)}"

    def serialize(self):
        import pickle
        serialized_privileges = pickle.dumps(sorted(list(self.privileges)))
        serialized_path = pickle.dumps(self.path)
        return {'privileges': serialized_privileges, 'path': serialized_path}

    @classmethod
    def deserialize(cls, buffer):
        if not isinstance(buffer, dict) or len(buffer) != 2:
            raise ValueError("Invalid buffer")
        privileges_bytes = buffer['privileges']
        path_bytes = buffer['path']
        deserialized_privileges = pickle.loads(privileges_bytes)
        deserialized_path = pickle.loads(path_bytes)
        return cls(deserialized_path)

    def __lt__(self, other):
        if not isinstance(other, PathPrivilege):
            raise ValueError("Invalid comparison")
        return self.reference_cnt > other.reference_cnt

REFERENCE_DESCENT_SORTER = lambda x, y: -int.__cmp__(x.reference_cnt, y.reference_cnt)
