Here is your Java code translated into Python:

```Python
import logging
from typing import List, Set, Dict, Any

class ClusterPlanExecutor:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def get_instance() -> 'ClusterPlanExecutor':
        return _cluster_plan_executor  # singleton instance

_cluster_plan_executor: ClusterPlanExecutor = None


def main():
    global _cluster_plan_executor
    if not _cluster_plan_executor:
        _cluster_plan_executor = ClusterPlanExecutor()
    return _cluster_plan_executor


class PartialPath:
    def __init__(self, path):
        self.path = path

    @staticmethod
    def from_string_list(paths: List[str]) -> 'PartialPath':
        # implementation omitted for brevity
        pass


def get_paths_name(path: PartialPath) -> Set[PartialPath]:
    return IoTDB.meta_manager.get_match_path(path)


class ClusterDescriptor:
    @staticmethod
    def get_instance() -> 'ClusterDescriptor':
        return _cluster_descriptor  # singleton instance

_cluster_descriptor = None


def main():
    global _cluster_descriptor
    if not _cluster_descriptor:
        _cluster_descriptor = ClusterDescriptor()
    return _cluster_descriptor


class IoTDBMetaManager:
    @staticmethod
    def get_instance() -> 'IoTDBMetaManager':
        return _iotdb_meta_manager  # singleton instance

_iotdb_meta_manager = None


def main():
    global _iotdb_meta_manager
    if not _iotdb_meta_manager:
        _iotdb_meta_manager = IoTDBMetaManager()
    return _iotdb_meta_manager


class StorageEngine:
    @staticmethod
    def get_instance() -> 'StorageEngine':
        return _storage_engine  # singleton instance

_storage_engine = None


def main():
    global _storage_engine
    if not _storage_engine:
        _storage_engine = StorageEngine()
    return _storage_engine


# usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cluster_plan_executor: ClusterPlanExecutor = main()

```

Note that this translation is based on the assumption that you want to keep your original Java code structure and naming conventions.