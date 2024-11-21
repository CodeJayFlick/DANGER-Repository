import enum
from collections import defaultdict, deque

class TSDataType(enum.Enum):
    pass  # define your own enum values here

class TVListAllocator:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.tv_list_cache = defaultdict(lambda: deque())

    @classmethod
    def get_instance(cls):
        return cls._instance

    def allocate(self, data_type: TSDataType) -> 'TVList':
        tv_lists = self.tv_list_cache[data_type]
        list_ = tv_lists.pop()
        if not list_:
            list_ = TVList(data_type)
        return list_

    def allocate_vector(self, data_types: list[TSDataType]) -> 'TVList':
        # implement your own logic for vector types
        pass

    def release(self, data_type: TSDataType, tv_list: 'TVList'):
        if data_type != TSDataType.VECTOR:
            self.tv_list_cache[data_type].append(tv_list)
        else:
            # handle VECTOR type separately
            pass

    @property
    def number_of_tv_lists(self) -> int:
        return sum(len(queue) for queue in self.tv_list_cache.values())

    def start(self):
        try:
            JMXService.register_mbean(self, self.mbean_name)
        except Exception as e:
            raise StartupException(f"Error starting TVListAllocator: {e}")

    def stop(self):
        JMXService.deregister_mbean(self.mbean_name)
        for queue in self.tv_list_cache.values():
            queue.clear()

    @property
    def mbean_name(self) -> str:
        return f"{IoTDBConstant.IOTDB_PACKAGE}:{IoTDBConstant.JMX_TYPE}={self.get_id().get_jmx_name()}"

    @property
    def get_id(self):
        # implement your own logic for getting the ID
        pass

class TVList:
    def __init__(self, data_type: TSDataType):
        self.data_type = data_type

    @classmethod
    def new_list(cls, data_type: TSDataType) -> 'TVList':
        return cls(data_type)

    # implement your own logic for the rest of the methods in TVList class
