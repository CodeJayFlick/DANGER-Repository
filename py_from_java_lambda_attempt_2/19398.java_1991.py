Here is the translation of the Java code to Python:
```
import skript

class AxolotlData(EntityData):
    def __init__(self, variant=None):
        self.variant = variant
        if variant is not None:
            self.matched_pattern = variant.ordinal + 1
        else:
            self.matched_pattern = 0

    @staticmethod
    def register():
        if hasattr(skript, 'class_exists') and skript.class_exists('org.bukkit.entity.Axolotl'):
            EntityData.register(AxolotlData, 'axolotl', Axolotl, 0,
                                 'axolotl', 'lucy axolotl', 'wild axolotl', 'gold axolotl', 'cyan axolotl', 'blue axolotl')

    def init(self, exprs=None):
        if self.matched_pattern > 0:
            self.variant = Variant.values()[self.matched_pattern - 1]
        return True

    @staticmethod
    def get_super_type():
        return AxolotlData(None)

    def set(self, entity):
        if self.variant is not None:
            entity.set_variant(self.variant)

    def match(self, entity):
        return self.variant is None or self.variant == entity.get_variant()

    def get_type(self):
        return type(Axolotl())

    @staticmethod
    def hash_code():
        if AxolotlData.variant is not None:
            return AxolotlData.variant.hash_code()
        else:
            return 0

    def equals(self, data):
        if isinstance(data, AxolotlData) and self.variant == data.variant:
            return True
        return False

    @staticmethod
    def is_supertype_of(data):
        if not isinstance(data, AxolotlData):
            return False
        return self.variant is None or self.variant == data.variant
```
Note that I had to make some assumptions about the Python code since it's a translation from Java. For example:

* In Java, `@Nullable` annotations are used to indicate that a variable can be null. In Python, we don't have explicit type hints for variables, so I simply omitted these checks.
* The `static { ... }` block in Java is equivalent to the `register()` method in Python.
* Some methods (e.g., `init`, `set`) take additional arguments that are not present in the original Java code. These were added based on my understanding of how they should behave.

Please let me know if you have any questions or need further clarification!