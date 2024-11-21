import logging
from collections import defaultdict, deque
from typing import List, Set, Dict, Tuple

class TsFileManager:
    def __init__(self, storage_group_name: str, virtual_storage_group: str, storage_group_dir: str):
        self.storage_group_name = storage_group_name
        self.virtual_storage_group = virtual_storage_group
        self.storage_group_dir = storage_group_dir
        self.resource_list_lock = threading.Lock()
        self.write_lock_holder = None

    def get_ts_file_list(self, sequence: bool) -> List['TsFileResource']:
        with self.resource_list_lock:
            if sequence:
                return list(self.sequence_files.values())
            else:
                return list(self.unsequence_files.values())

    def get_sequence_list_by_time_partition(self, time_partition: int) -> 'TsFileResourceList':
        return self.sequence_files.setdefault(time_partition, TsFileResourceList())

    def get_unsequence_list_by_time_partition(self, time_partition: int) -> 'TsFileResourceList':
        return self.unsequence_files.setdefault(time_partition, TsFileResourceList())

    def get_iterator(self, sequence: bool) -> Iterator['TsFileResource']:
        with self.resource_list_lock:
            if sequence:
                return iter(self.get_ts_file_list(sequence))
            else:
                return iter(self.get_ts_file_list(not sequence))

    def remove(self, ts_file_resource: 'TsFileResource', sequence: bool):
        with self.resource_list_lock:
            if sequence:
                for entry in self.sequence_files.items():
                    if entry[1].remove(ts_file_resource):
                        TsFileResourceManager.getInstance().remove_ts_file_resource(ts_file_resource)
                        break
            else:
                for entry in self.unsequence_files.items():
                    if entry[1].remove(ts_file_resource):
                        TsFileResourceManager.getInstance().remove_ts_file_resource(ts_file_resource)
                        break

    def remove_all(self, ts_file_resources: List['TsFileResource'], sequence: bool):
        with self.resource_list_lock:
            for resource in ts_file_resources:
                self.remove(resource, sequence)

    def insert_to_partition_file_list(
        self,
        ts_file_resource: 'TsFileResource',
        sequence: bool,
        insert_pos: int
    ):
        with self.resource_list_lock:
            if sequence:
                list_ = self.sequence_files.setdefault(ts_file_resource.time_partition, TsFileResourceList())
                list_.insert(insert_pos, ts_file_resource)
            else:
                list_ = self.unsequence_files.setdefault(ts_file_resource.time_partition, TsFileResourceList())
                list_.insert(insert_pos, ts_file_resource)

    def add(self, ts_file_resource: 'TsFileResource', sequence: bool):
        with self.resource_list_lock:
            if sequence:
                self.sequence_files[ts_file_resource.time_partition].add(ts_file_resource)
            else:
                self.unsequence_files[ts_file_resource.time_partition].add(ts_file_resource)

    def add_for_recover(self, ts_file_resource: 'TsFileResource', sequence: bool):
        if sequence:
            self.sequence_recover_ts_file_resources.appendleft(ts_file_resource)
        else:
            self.unsequence_recover_ts_file_resources.appendleft(ts_file_resource)

    def add_all(self, ts_file_resources: List['TsFileResource'], sequence: bool):
        with self.resource_list_lock:
            for resource in ts_file_resources:
                self.add(resource, sequence)

    def contains(self, ts_file_resource: 'TsFileResource', sequence: bool) -> bool:
        with self.resource_list_lock:
            if sequence:
                return ts_file_resource.time_partition in self.sequence_files and \
                       self.sequence_files[ts_file_resource.time_partition].contains(ts_file_resource)
            else:
                return ts_file_resource.time_partition in self.unsequence_files and \
                       self.unsequence_files[ts_file_resource.time_partition].contains(ts_file_resource)

    def clear(self):
        with self.resource_list_lock:
            self.sequence_files.clear()
            self.unsequence_files.clear()

    def is_empty(self, sequence: bool) -> bool:
        with self.resource_list_lock:
            if sequence:
                return not any(list_.size() > 0 for list_ in self.sequence_files.values())
            else:
                return not any(list_.size() > 0 for list_ in self.unsequence_files.values())

    def size(self, sequence: bool) -> int:
        with self.resource_list_lock:
            if sequence:
                total_size = sum(len(list_) for list_ in self.sequence_files.values())
                return total_size
            else:
                total_size = sum(len(list_) for list_ in self.unsequence_files.values())
                return total_size

    def read_lock(self):
        with self.resource_list_lock:
            pass

    def read_unlock(self):
        with self.resource_list_lock:
            pass

    def write_lock(self, holder: str):
        with self.resource_list_lock:
            self.write_lock_holder = holder

    def write_lock_with_timeout(self, holder: str, timeout: int) -> None:
        if not self.resource_list_lock.acquire(timeout=timeout):
            raise WriteLockFailedException(f"Cannot get write lock in {timeout} ms")

    def write_unlock(self):
        with self.resource_list_lock:
            self.write_lock_holder = ""
            self.resource_list_lock.release()

    @property
    def storage_group_name(self) -> str:
        return self.storage_group_name

    @storage_group_name.setter
    def storage_group_name(self, value: str):
        self.storage_group_name = value

    @property
    def virtual_storage_group(self) -> str:
        return self.virtual_storage_group

    @virtual_storage_group.setter
    def virtual_storage_group(self, value: str):
        self.virtual_storage_group = value

    @property
    def storage_group_dir(self) -> str:
        return self.storage_group_dir

    @storage_group_dir.setter
    def storage_group_dir(self, value: str):
        self.storage_group_dir = value

    @property
    def sequence_recover_ts_file_resources(self) -> List['TsFileResource']:
        return self.sequence_recover_ts_file_resources

    @sequence_recover_ts_file_resources.setter
    def sequence_recover_ts_file_resources(self, value: List['TsFileResource']):
        self.sequence_recover_ts_file_resources = value

    @property
    def unsequence_recover_ts_file_resources(self) -> List['TsFileResource']:
        return self.unsequence_recover_ts_file_resources

    @unsequence_recover_ts_file_resources.setter
    def unsequence_recover_ts_file_resources(self, value: List['TsFileResource']):
        self.unsequence_recover_ts_file_resources = value

def compare_filename(o1: File, o2: File) -> int:
    items1 = o1.name.replace(TSFILE_SUFFIX, "").split(FILE_NAME_SEPARATOR)
    items2 = o2.name.replace(TSFILE_SUFFIX, "").split(FILE_NAME_SEPARATOR)
    ver1 = int(items1[0])
    ver2 = int(items2[0])
    cmp = (ver1 - ver2) if ver1 < ver2 else 0
    return cmp

class TsFileResourceList:
    def __init__(self):
        self.list_ = deque()

    def add(self, ts_file_resource: 'TsFileResource'):
        self.list_.appendleft(ts_file_resource)

    def remove(self, ts_file_resource: 'TsFileResource') -> bool:
        return self.list_.remove(ts_file_resource) is not None

    def contains(self, ts_file_resource: 'TsFileResource') -> bool:
        return ts_file_resource in self.list_

    @property
    def size(self) -> int:
        return len(self.list_)

class TsFileManagerConstant:
    TSFILE_SUFFIX = ".tsfile"
    FILE_NAME_SEPARATOR = "-"
