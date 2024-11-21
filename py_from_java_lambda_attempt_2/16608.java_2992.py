Here's your Java code translated into equivalent Python:

```Python
import logging
from typing import List

class ClusterQueryUtils:
    logger = logging.getLogger(__name__)

    def __init__(self):
        # util class
        pass

    @staticmethod
    def check_path_existence(path: str) -> None:
        try:
            check_path_existence(PartialPath(path))
        except IllegalPathException as e:
            raise QueryProcessException(e)

    @staticmethod
    def check_path_existence(path: 'PartialPath') -> None:
        if not IoTDB.meta_manager.is_path_exists(path):
            MetaPuller.get_instance().pull_time_series_schemas([path], None)
        else:
            pass

    @staticmethod
    def check_path_existence(paths: List['PartialPath']) -> None:
        for path in paths:
            ClusterQueryUtils.check_path_existence(path)

    @staticmethod
    def get_path_str_list_for_request(path: 'Path') -> List[str]:
        if isinstance(path, VectorPartialPath):
            return [path.get_full_path()] + list(path.get_sub_sensors_list())
        else:
            return [path.get_full_path()]

    @staticmethod
    def assembled_path_from_request(path_string: List[str]) -> 'PartialPath':
        try:
            if len(path_string) == 1:
                return PartialPath(path_string[0])
            elif path_string[0] is not None and len(path_string) > 1:
                return VectorPartialPath(path_string[0], path_string[1:])
            else:
                raise IllegalPathException("Failed to create partial path")
        except Exception as e:
            ClusterQueryUtils.logger.error(f"Failed to create partial path, full_path is {path_string}, error: {e}")
            return None


class PartialPath:
    def __init__(self, path):
        self.path = path

    @property
    def get_full_path(self) -> str:
        return self.path


class VectorPartialPath(PartialPath):
    def __init__(self, full_path, sub_sensors_list):
        super().__init__(full_path)
        self.sub_sensors_list = sub_sensors_list

    @property
    def get_sub_sensors_list(self) -> List[str]:
        return self.sub_sensors_list


class IoTDB:
    meta_manager: 'IoTDBMetaManager'

    class MetaManager:
        pass

    @staticmethod
    def meta_manager() -> 'IoTDB.MetaManager':
        # todo implement this method
        raise NotImplementedError("Method not implemented")


class QueryProcessException(Exception):
    pass


class IllegalPathException(Exception):
    pass


# todo implement these classes and methods
MetaPuller = None  # type: MetaPuller
```

Note that Python does not have direct equivalent of Java's `Logger` class. Instead, you can use the built-in `logging` module to achieve similar functionality.