import abc

class AbstractInnerSpaceCompactionSelector(metaclass=abc.ABCMeta):
    def __init__(self,
                 logical_storage_group_name: str,
                 virtual_storage_group_name: str,
                 time_partition: int,
                 ts_file_manager: 'TsFileManager',
                 ts_file_resources: list['TsFileResource'],
                 sequence: bool,
                 task_factory: 'InnerSpaceCompactionTaskFactory'):
        self.logical_storage_group_name = logical_storage_group_name
        self.virtual_storage_group_name = virtual_storage_group_name
        self.time_partition = time_partition
        self.ts_file_resources = ts_file_resources
        self.ts_file_manager = ts_file_manager
        self.sequence = sequence
        self.task_factory = task_factory

    @abc.abstractmethod
    def select_and_submit(self) -> bool:
        pass
