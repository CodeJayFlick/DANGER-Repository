Here is the translation of the given Java code into Python:

```Python
class NameSymbol:
    def __init__(self, location):
        self.location = location
        self.nametable = []
        self.table_is_filled = False

    def __init__(self, location, name, pattern_value, nametable):
        super().__init__(location)
        self.name = name
        self.pattern_value = pattern_value
        self.nametable = nametable
        self.check_table_fill()

    def check_table_fill(self):
        min_val = self.pattern_value.min_value()
        max_val = self.pattern_value.max_value()
        self.table_is_filled = (min_val >= 0) and (max_val < len(self.nametable))
        for i in range(len(self.nametable)):
            if self.nametable[i] is None:
                self.table_is_filled = False
                break

    def resolve(self, parser_walker):
        if not self.table_is_filled:
            index = int(self.pattern_value.get_value(parser_walker))
            if (index >= len(self.nametable)) or (index < 0) or (self.nametable[index] == ""):
                raise BadDataError(f"No corresponding entry in nametable {self.name}, index={index}")
        return None

    def get_type(self):
        return "name_symbol"

    def print(self, s, parser_walker):
        index = int(self.pattern_value.get_value(parser_walker))
        # ind is already checked to be in range by the resolve routine
        s.print(self.nametable[index])

    def save_xml(self, s):
        s.write("<name_sym>")
        self.save_sleigh_symbol_xml_header(s)
        s.write(">")
        self.pattern_value.save_xml(s)
        for i in range(len(self.nametable)):
            name = self.nametable[i]
            if name is not None:
                s.write(f"<nametab name=\"{name}\"/>")
            else:
                s.write("<nametab/>")
        s.write("</name_sym>")

    def save_xml_header(self, s):
        s.write("<name_sym_head>")
        self.save_sleigh_symbol_xml_header(s)
        s.write("/>")

    def restore_xml(self, el, trans):
        list = el.getchildren()
        iterator = iter(list)
        element = next(iterator)
        self.pattern_value = PatternExpression.restore_expression(element, trans)
        self.pattern_value.lay_claim()
        while True:
            try:
                child = next(iterator)
            except StopIteration:
                break
            self.nametable.append(child.get("name"))
        self.check_table_fill()

class BadDataError(Exception):
    pass

class SleighBase:
    def __init__(self, location):
        self.location = location

class PatternValue:
    def __init__(self, min_value=0, max_value=float('inf')):
        self.min_value = min_value
        self.max_value = max_value

    def get_value(self, parser_walker):
        pass  # implement this method in the subclass

    def lay_claim():
        pass  # implement this method in the subclass

class PatternExpression:
    @staticmethod
    def restore_expression(element, trans):
        pass  # implement this method in the subclass
```

Note that some methods like `get_value`, `lay_claim` and `restore_expression` are not implemented as they were part of a larger class hierarchy.