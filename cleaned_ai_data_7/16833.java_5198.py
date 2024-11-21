import logging
from typing import Dict

class TSFRecordWriter:
    def __init__(self, job: dict, path: str, schema: dict) -> None:
        self.logger = logging.getLogger(__name__)
        self.writer = TsFileWriter(path, job['configuration'], False, schema)

    def write(self, key: int, value: Dict):
        try:
            self.writer.write(value)
        except WriteProcessException as e:
            raise Exception(f"Write tsfile record error {e}")

    def close(self) -> None:
        self.logger.info("Close the record writer")
        self.writer.close()

class TsFileWriter:
    def __init__(self, path: str, configuration: dict, overwrite: bool, schema: dict):
        pass

    def write(self, value: Dict) -> None:
        # implement your logic here
        pass

    def close(self) -> None:
        pass
