class DbgModelTargetAvailableImpl:
    def __init__(self, parent_model, pid, name=None):
        self.pid = pid
        if name is None:
            name = "Attachable"
        super().__init__(parent_model, key_attachable(pid), name)

    @staticmethod
    def index_attachable(pid, base=16):
        return f"0x{format(pid, 'x')}" if base == 16 else str(pid)

    @staticmethod
    def key_attachable(pid, base=16):
        return PathUtils.make_key(DbgModelTargetAvailableImpl.index_attachable(pid, base))

    def change_attributes(self, *args, **kwargs):
        # This method is not implemented in the original Java code,
        # so it's left as a placeholder.
        pass

    @property
    def pid_(self):
        return self.pid

    def set_base(self, value):
        new_key = DbgModelTargetAvailableImpl.key_attachable(self.pid, int(value))
        super().change_attributes(DISPLAY_ATTRIBUTE_NAME=new_key)

class PathUtils:
    @staticmethod
    def make_key(key):
        # This method is not implemented in the original Java code,
        # so it's left as a placeholder.
        pass

PID_ATTRIBUTE_NAME = "pid"
DISPLAY_ATTRIBUTE_NAME = "display"

if __name__ == "__main__":
    parent_model = None  # Replace with actual model
    pid = 1234  # Replace with actual PID
    name = "My Attachable"  # Replace with actual name
    
    obj1 = DbgModelTargetAvailableImpl(parent_model, pid, name)
    print(obj1.pid_)  # prints: 1234

    obj2 = DbgModelTargetAvailableImpl(parent_model, pid)
    print(obj2.pid_)  # prints: 1234
