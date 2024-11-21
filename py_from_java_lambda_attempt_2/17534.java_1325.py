Here is a translation of the Java UDTFMatches class into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's UDTF, UDFParameterValidator, PointCollector and TSDataType. This translation is based on the functionality provided by these classes in the original code.

In this translation:

- The `validate` method checks if the input parameters are valid.
- The `before_start` method compiles a regular expression pattern from the 'regex' parameter.
- The `transform` method applies the compiled regex pattern to each row of data and outputs a boolean value indicating whether the match was successful.