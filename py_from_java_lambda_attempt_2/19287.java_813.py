Here is the translation of the given Java code into Python:

```Python
class CondResourcePack:
    def __init__(self):
        self.states = None

    @staticmethod
    def register_condition():
        Skript.register_condition(CondResourcePack, 
                                 "[the] resource pack (was|is|has) %resourcepackstate%", 
                                 "[the] resource pack (was|is|has)(n' t| not) %resourcepackstate%")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not Skript.is_current_event(PlayerResourcePackStatusEvent):
            print("The resource pack condition can't be used outside of a resource pack response event")
            return False
        self.states = exprs[0]
        self.set_negated(matched_pattern == 1)
        return True

    def check(self, e):
        state = (e).getStatus()
        return self.states.check(e, lambda x: x == state, self.is_negated())

    def __str__(self, e, debug=False):
        if self.is_negated():
            prefix = "not "
        else:
            prefix = ""
        return f"resource pack was {prefix}{self.states.__str__(e, debug)}"

class Skript:
    @staticmethod
    def register_condition(cls):
        pass

    @staticmethod
    def is_current_event(event_class):
        # This method should be implemented based on the actual usage of events in your program.
        return False

# Usage example:

cond = CondResourcePack()
exprs = ["some expression"]
matched_pattern = 0
is_delayed = True
parse_result = "some parse result"
if cond.init(exprs, matched_pattern, is_delayed, parse_result):
    event = PlayerResourcePackStatusEvent() # This should be replaced with the actual event object.
    if cond.check(event):
        print("The resource pack was accepted")
    else:
        print("The resource pack wasn't accepted")

print(cond)  # prints: "resource pack was [the state of the resource pack]"
```

Please note that this translation is not a direct conversion from Java to Python. It's more like an interpretation, as some parts might be missing or modified based on how they would work in Python.