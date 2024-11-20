Here is the translation of the given Java code into Python:

```Python
class EffReplace:
    def __init__(self):
        self.haystack = None
        self.needles = None
        self.replacement = None
        self.replace_string = True
        self.replace_first = False
        self.case_sensitive = False

    @staticmethod
    def register_effect():
        Skript.register_effect(EffReplace, [
            "replace (all|every) %strings% in %strings% with %string% [(1¦with case sensitivity)]",
            "replace (all|every) %strings% with %string% in %strings% [(1¦with case sensitivity)]",
            "replace first %strings% in %strings% with %string% [(1¦with case sensitivity)]",
            "replace first %strings% with %string% in %string% [(1¦with case sensitivity)]",
            "replace (all|every) %itemtypes% in %inventories% with %itemtype%",
            "replace (all|every) %itemtypes% with %itemtype% in %inventories%"
        ])

    def init(self, exprs, matched_pattern):
        self.haystack = exprs[1 + matched_pattern % 2]
        if matched_pattern < 4:
            self.replace_string = True
            self.replace_first = matched_pattern > 1 and matched_pattern < 4
        else:
            self.replace_string = False
            self.replace_first = False

        if SkriptConfig.case_sensitive.value() or matched_pattern == 1:
            self.case_sensitive = True

        self.needles = exprs[0]
        self.replacement = exprs[2 - matched_pattern % 2]

    def execute(self, e):
        haystack = list(self.haystack)
        needles = list(self.needles)

        if not self.replace_string:
            for inv in [Inventory(i) for i in haystack]:
                for item in needles:
                    for slot in inv.all(item).keys():
                        inv.set_item(slot, replacement=item.get_random())

        else:
            if self.replace_first:
                for x in range(len(haystack)):
                    for n in needles:
                        haystack[x] = re.sub(n, Matcher.quoteReplacement(str(self.replacement)), case_sensitive=self.case_sensitive)
            else:
                for x in range(len(haystack)):
                    for n in needles:
                        haystack[x] = re.sub(n, str(self.replacement), case_sensitive=self.case_sensitive)

        self.haystack.change(e, haystack, ChangeMode.SET)

    def __str__(self):
        if self.replace_first:
            return f"replace first {self.needles} in {self.haystack} with {self.replacement}(case sensitive: {self.case_sensitive})"
        else:
            return f"replace {self.needles} in {self.haystack} with {self.replacement}(case sensitive: {self.case_sensitive})"

class Inventory(dict):
    def all(self, item_type):
        return self

    def set_item(self, slot, item):
        pass
```

Note that this translation is not a direct conversion from Java to Python. Some changes were made to make the code more idiomatic and efficient in Python.