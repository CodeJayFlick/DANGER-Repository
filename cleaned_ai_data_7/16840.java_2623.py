import logging
from typing import List, Dict

class TSFHiveRecordReader:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.data_set_list: List[Dict] = []
        self.device_id_list: List[str] = []
        self.current_index: int = 0
        self.is_read_device_id: bool = False
        self.is_read_time: bool = False

    def next(self, key=None, value=None) -> bool:
        while self.current_index < len(self.data_set_list):
            if not self.data_set_list[self.current_index]['has_next']:
                self.current_index += 1
            else:
                row_record = self.data_set_list[self.current_index]['next']
                fields: List[Dict] = row_record['fields']
                timestamp: int = row_record['timestamp']

                try:
                    res: Dict[str, str] = {}
                    for k, v in getCurrentValue(self.device_id_list,
                                                  self.current_index,
                                                  timestamp,
                                                  self.is_read_time,
                                                  self.is_read_device_id,
                                                  fields).items():
                        res[k.lower()] = v
                    value.update(res)
                except Exception as e:
                    raise ValueError(str(e))

                return True

        return False

    def create_key(self) -> None:
        return None

    def create_value(self) -> Dict[str, str]:
        return {}

    def get_pos(self) -> int:
        # can't know
        return 0


class TSFInputSplit:
    pass


def initialize(split: TSFHiveRecordReader, job=None):
    if isinstance(split, TSFHiveRecordReader):
        TSFRecordReader.initialize((TSFInputSplit), job, split.data_set_list, split.device_id_list)
    else:
        logging.error(f"The InputSplit class is not {TSFHiveRecordReader}, the class is {split.__class__.__name__}")
        raise InternalError(f"The InputSplit class is not {TSFHiveRecordReader}, the class is {split.__class__.__name__}")


def get_progress(self) -> float:
    return 0


def close(self):
    self.data_set_list = None
    self.device_id_list = None
