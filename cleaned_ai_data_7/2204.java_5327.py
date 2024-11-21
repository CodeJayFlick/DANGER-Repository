class TargetObjectPath:
    def __init__(self, model: 'DebuggerObjectModel', key_list):
        self.model = model
        self.key_list = key_list
        self.hash = hash((model, tuple(key_list)))

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, TargetObjectPath):
            return False
        else:
            return (self.model == other.model) and (self.key_list == other.key_list)

    def __hash__(self):
        return hash((self.model, tuple(self.key_list)))

    def __lt__(self, other):
        if self is other:
            return False

        this_model = self.model
        that_model = other.model

        if this_model != that_model:
            if this_model is None:
                return True
            elif that_model is None:
                return False
            else:
                result = str(this_model).lower() < str(that_model).lower()
                if not result:
                    return hash(self.model) < hash(other.model)
                return result

        return PathComparator.KEYED.compare(tuple(self.key_list), tuple(other.key_list))

    def __str__(self):
        return f"<{self.to_path_string()} in {self.model}>"

    @property
    def model_(self):
        return self.model

    @property
    def key_list_(self):
        return self.key_list

    def name(self):
        return PathUtils.get_key(tuple(self.key_list))

    def index(self):
        return PathUtils.get_index(tuple(self.key_list))

    def is_root(self):
        return not bool(self.key_list)

    async def fetch(self) -> 'TargetObject':
        return await self.model.fetch_model_object(tuple(self.key_list))

    def to_path_string(self):
        return str(PathUtils.to_string(tuple(self.key_list)))

    @property
    def parent_(self):
        pkl = PathUtils.parent(tuple(self.key_list))
        if pkl is None:
            return None
        else:
            return TargetObjectPath(self.model, tuple(pkl))

    def successor(self, sub_key_list: list) -> 'TargetObjectPath':
        return TargetObjectPath(self.model, PathUtils.extend(tuple(self.key_list), tuple(sub_key_list)))

    def successor_(self, *sub_key_list):
        return self.successor(list(sub_key_list))
