class AbstractGdbLibraryEvent:
    def __init__(self, tail):
        super().__init__()
        self.lid = GdbLibraryId(tail.get("id"))
        self.target_name = tail.get("target-name")
        thread_group_gid = tail.get("thread-group", None)
        if thread_group_gid is None:
            self.iid = None
        else:
            self.iid = int(thread_group_gid)

    def get_library_id(self):
        return self.lid

    def get_target_name(self):
        return self.target_name

    def get_inferior_id(self):
        return self.iid


class GdbLibraryId:
    def __init__(self, id):
        self.id = id

    def __eq__(self, other):
        if not isinstance(other, GdbLibraryId):
            return False
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)


class GdbParseError(Exception):
    pass


def parse_inferior_id(gid):
    try:
        return int(gid)
    except ValueError:
        raise GdbParseError("Invalid inferior ID")
