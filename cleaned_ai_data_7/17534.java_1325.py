import re
from typing import Any

class UDTFMatches:
    def __init__(self):
        self.pattern = None

    def validate(self, parameters: dict) -> None:
        if 'regex' not in parameters or len(parameters['input_series']) != 1:
            raise Exception('Invalid input')

    def before_start(self, parameters: dict) -> None:
        regex_pattern = re.compile(parameters.get('regex', ''))

        self.pattern = regex_pattern

    def transform(self, row: Any, collector: Any) -> None:
        if not isinstance(row[0], str):
            raise Exception('Invalid input type')

        try:
            match_result = bool(self.pattern.match(str(row[0])))
            collector.put_boolean(row.get_time(), match_result)
        except Exception as e:
            print(f"Error in transform function: {str(e)}")
