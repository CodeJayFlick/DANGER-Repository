Here is the translation of the given Java code into Python:

```Python
class AbstractGdbThreadEvent:
    def __init__(self, tail):
        self.tid = int(tail["id"])
        self.iid = GdbParsingUtils.parse_inferior_id(tail.get("group-id", ""))

    @property
    def tid(self):
        return self._tid

    @property
    def iid(self):
        return self._iid


class GdbParsingUtils:
    @staticmethod
    def parse_inferior_id(group_id):
        # implement this method as per your requirement
        pass
```

Note that I've used Python's property decorator to create getter methods for `tid` and `iid`, which is equivalent to the Java getters. The constructor (`__init__`) takes a single argument, `tail`, which contains the parsed information from GDB/MI event record.

The `GdbParsingUtils.parse_inferior_id()` method needs to be implemented based on your specific requirements for parsing inferior IDs.