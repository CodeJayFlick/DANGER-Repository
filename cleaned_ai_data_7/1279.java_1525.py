class AbstractGdbThreadEvent:
    def __init__(self, tail):
        self.tid = int(tail["id"])
        self.iid = GdbParsingUtils.parse_inferior_id(tail.get("group-id", ""))

    @property
    def tid(self):
        return self._tid

    @property
    def iid(self):
        return self._iid


class GdbParsingUtils:
    @staticmethod
    def parse_inferior_id(group_id):
        # implement this method as per your requirement
        pass
