class MNodePlan:
    def __init__(self):
        self.name = None
        self.child_size = 0

    def __str__(self):
        return f"MNode({self.name},{self.child_size})"

    def get_paths(self):
        return []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def child_size(self):
        return self._child_size

    @child_size.setter
    def child_size(self, value):
        self._child_size = value


def serialize_to_buffer(mnode_plan: MNodePlan) -> bytes:
    buffer = bytearray()
    buffer.extend((mnode_plan.name).encode())
    buffer.append(int.to_bytes(1, 4, 'big'))
    return buffer

def deserialize_from_buffer(buffer: bytes) -> MNodePlan:
    mnode_plan = MNodePlan()
    if len(buffer):
        mnode_plan.name = buffer.decode().split(',')[0]
        mnode_plan.child_size = int.from_bytes(buffer[buffer.index(b'\x00'):], 'big')
    return mnode_plan
