import re

class StringMatchQuery:
    def __init__(self, col, search_string, case_sensitive):
        self.col = col
        if not case_sensitive:
            search_string = f".*{re.escape(search_string)}.*"
        else:
            search_string = re.escape(search_string)
        pattern = re.compile(search_string)

    def matches(self, record):
        value = str(record[self.col])
        return bool(re.fullmatch(self.pattern, value))
