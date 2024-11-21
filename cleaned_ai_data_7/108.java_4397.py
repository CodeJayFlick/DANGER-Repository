class MemviewBoxType:
    INSTRUCTIONS = 'INSTRUCTIONS'
    PROCESS = 'PROCESS'
    THREAD = 'THREAD'
    MODULE = 'MODULE'
    REGION = 'REGION'
    IMAGE = 'IMAGE'
    VIRTUAL_ALLOC = 'VIRTUAL_ALLOC'
    HEAP_CREATE = 'HEAP_CREATE'
    HEAP_ALLOC = 'HEAP_ALLOC'
    POOL = 'POOL'
    STACK = 'STACK'
    PERFINFO = 'PERFINFO'
    READ_MEMORY = 'READ_MEMORY'
    WRITE_MEMORY = 'WRITE_MEMORY'
    BREAKPOINT = 'BREAKPOINT'

colors = {
    MemviewBoxType.INSTRUCTIONS: (128, 0, 0),
    MemviewBoxType.PROCESS: (200, 200, 255),
    MemviewBoxType.THREAD: (200, 255, 255),
    MemviewBoxType.MODULE: 'green',
    MemviewBoxType.REGION: 'yellow',
    MemviewBoxType.IMAGE: 'magenta',
    MemviewBoxType.VIRTUAL_ALLOC: '#cccccc',  # light gray
    MemviewBoxType.HEAP_CREATE: 'blue',
    MemviewBoxType.HEAP_ALLOC: (0, 100, 50),
    MemviewBoxType.POOL: (100, 0, 150),
    MemviewBoxType.STACK: 'cyan',
    MemviewBoxType.PERFINFO: '#cccccc',  # light gray
    MemviewBoxType.READ_MEMORY: 'darkgray',
    MemviewBoxType.WRITE_MEMORY: 'blue',
}

def get_color(self):
    return colors[self]

# Note that Python does not have an equivalent to Java's enum, so we're using a class instead.
class MemviewBoxType:
    def __init__(self, value):
        self.value = value

    def get_color(self):
        return colors.get(self.value)

memview_box_type = MemviewBoxType
