Here is the translation of the given Java code into Python:

```Python
import re

class RegExSearchData:
    def __init__(self, input_string):
        self.pattern = None
        try:
            self.pattern = re.compile(input_string, flags=re.DOTALL)
        except re.error as e:
            self.errorMessage = str(e)

    @staticmethod
    def create_reg_ex_search_data(input_string):
        reg_ex_search_data = RegExSearchData(input_string)
        if hasattr(reg_ex_search_data, 'errorMessage'):
            raise ValueError(f"Problem creating search data: {reg_ex_search_data.errorMessage}")
        return reg_ex_search_data

    def is_valid_search_data(self):
        return self.pattern is not None

    def get_reg_ex_pattern(self):
        return self.pattern
```

Please note that Python does not have a direct equivalent to Java's `PatternSyntaxException`. Instead, we catch the `re.error` exception which is raised when there is an error in the regular expression.