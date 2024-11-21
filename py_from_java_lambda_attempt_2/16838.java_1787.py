Here is a translation of the Java code into equivalent Python code:

```Python
import logging
from typing import List

class TSFHiveInputFormat:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_record_reader(self, split: str, job_config: dict, reporter) -> None:
        return TSFHiveRecordReader(split, job_config)

    def get_splits(self, job_config: dict, num_splits: int) -> List[dict]:
        job_config['input.dir.recurse'] = True
        splits = TSFInputFormat.get_tsf_input_split(job_config, [super().list_status(job_config)], self.logger)
        return list(splits)

class TSFHiveRecordReader:
    def __init__(self, split: str, job_config: dict):
        pass

# Usage example:

if __name__ == "__main__":
    input_format = TSFHiveInputFormat()
    # Call the methods
```

Please note that Python does not have direct equivalents for Java classes like `FileInputFormat`, `JobConf`, and `Reporter`. We've replaced them with more general-purpose constructs.