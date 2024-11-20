class GdbThreadSelectedEvent:
    def __init__(self, tail):
        self.tid = int(tail.split(' ')[-1].split('=')[1])

    @property
    def tid(self):
        return self._tid

    def get_frame(self, thread):
        fields = [field for field in getInfo().fields if 'frame' in field]
        if not fields:
            return None
        else:
            return GdbStackFrameImpl(thread, fields[0])

class AbstractGdbEventWithFields:
    def __init__(self, tail):
        self.info = {'id': int(tail.split(' ')[-1].split('=')[1])}

    @property
    def info(self):
        return self._info

def getInfo():
    # implement this function to get the necessary information from GDB/MI event record
    pass


class GdbStackFrameImpl:
    @classmethod
    def from_field_list(cls, thread, fields):
        # implement this method to create a new stack frame based on the given field list and thread
        pass

class GdbThreadImpl:
    pass  # implement this class as needed for your application
