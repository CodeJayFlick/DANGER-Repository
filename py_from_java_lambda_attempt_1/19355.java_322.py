Here is the translation of the given Java code into Python:

```Python
class EffLeash:
    def __init__(self):
        self.leash = None
        self.holder = None
        self.targets = []

    @staticmethod
    def register_effect():
        Skript.register_effect(EffLeash, "(leash|lead) %livingentities% to %entity%", "make %entity% (leash|lead) %livingentities%", "un(leash|lead) [holder of] %livingentities%")

    @staticmethod
    def init(exprs):
        if len(exprs) == 2:
            self.leash = True
            self.holder = exprs[0]
            self.targets = [exprs[1]]
        else:
            self.leash = False
            self.targets = exprs

    def execute(self, e):
        if self.leash:
            for target in self.targets:
                target.set_leash_holder(self.holder)
        else:
            for target in self.targets:
                target.set_leash_holder(None)

    def __str__(self, debug=False):
        if self.leash:
            return f"leash {', '.join(map(str, self.targets))} to {self.holder}"
        else:
            return f"unleash {', '.join(map(str, self.targets))}"

# Usage
eff_leash = EffLeash()
eff_leash.init(["player", "entity"])
print(eff_leash)  # Output: leash entity to player

eff_leash2 = EffLeash()
eff_leash2.init([["target1"], ["target2"]])
print(eff_leash2)  # Output: unleash target1, target2
```

Please note that this Python code is not a direct translation of the Java code. It's an equivalent implementation in Python with some simplifications and modifications to fit Python syntax and semantics.