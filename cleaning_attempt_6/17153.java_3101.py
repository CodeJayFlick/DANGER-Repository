class MNode:
    def __init__(self, parent: 'IMNode', name: str):
        self.parent = parent
        self.name = name

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def parent(self) -> 'IMNode':
        return self._parent

    @parent.setter
    def parent(self, value: 'IMNode'):
        self._parent = value

    def get_partial_path(self) -> PartialPath:
        if self.full_path is not None:
            try:
                return PartialPath(self.full_path)
            except IllegalPathException:
                pass
        detached_path = []
        temp = self
        while temp.parent is not None:
            detached_path.insert(0, temp.name)
            temp = temp.parent
        return PartialPath(detached_path)

    def get_full_path(self) -> str:
        if self.full_path is None:
            self.full_path = self.concat_full_path()
            cached_pool = CachedStringPool().get_cached_pool()
            if cached_pool.get(self.full_path) is not None:
                self.full_path = cached_pool.get(self.full_path)
        return self.full_path

    def concat_full_path(self) -> str:
        builder = StringBuilder(self.name)
        curr = self
        while curr.parent is not None:
            curr = curr.parent
            builder.insert(0, IoTDBConstant.PATH_SEPARATOR).insert(0, curr.name)
        return builder.toString()

    @full_path.setter
    def full_path(self, value: str):
        self._full_path = value

    def set_full_path(self, value: str) -> None:
        self.full_path = value

    def is_empty_internal(self) -> bool:
        return not IoTDBConstant.PATH_ROOT == self.name and \
               not self.is_storage_group() and \
               not self.is_measurement() and \
               self.schema_template is None and \
               not self.use_template and \
               len(self.children) == 0

    def is_use_template(self) -> bool:
        return False

    def is_storage_group(self) -> bool:
        return False

    def is_entity(self) -> bool:
        return False

    def is_measurement(self) -> bool:
        return False

    def get_as_storage_group_mnode(self) -> 'IStorageGroupMNode':
        if self.is_storage_group():
            return self
        else:
            raise UnsupportedOperationException("Wrong MNode Type")

    def get_as_entity_mnode(self) -> 'IEntityMNode':
        if self.is_entity():
            return self
        else:
            raise UnsupportedOperationException("Wrong MNode Type")

    def get_as_measurement_mnode(self) -> 'IMeasurementMNode':
        if self.is_measurement():
            return self
        else:
            raise UnsupportedOperationException("Wrong MNode Type")

    def __eq__(self, other):
        if self is other:
            return True
        if other is None or type(self) != type(other):
            return False
        if self.full_path is None:
            return self.get_full_path() == other.get_full_path()
        else:
            return self.full_path == other.full_path

    def __hash__(self):
        if self.full_path is None:
            return hash(self.get_full_path())
        else:
            return hash(self.full_path)

    def __str__(self) -> str:
        return self.name
