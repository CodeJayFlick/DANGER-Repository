Here is the translation of the given Java code into Python:

```Python
class AbstractProgramContext:
    def __init__(self, language):
        self.language = language
        self.base_context_register = language.get_base_processor_context()
        self.default_disassembly_context = RegisterValue(self.base_context_register)

        self.non_flowing_context_register_mask = list(self.base_context_register.get_base_mask())
        self.flowing_context_register_mask = list(self.base_context_register.get_base_mask())

    def get_language(self):
        return self.language

    def init_context_bit_masks(self, context_reg):
        sub_mask = list(context_reg.get_base_mask())
        if not context_reg.follows_flow():
            self.has_non_flowing_context = True
            for i in range(len(sub_mask)):
                self.non_flowing_context_register_mask[i] |= sub_mask[i]
                self.flowing_context_register_mask[i] &= ~sub_mask[i]

    def has_non_flowing_context(self):
        return self.has_non_flowing_context

    def get_flow_value(self, value):
        if not (value and self.has_non_flowing_context) or not value.get_register().is_processor_context():
            return value
        return value.clear_bit_values(list(map(lambda x: int(x), self.non_flowing_context_register_mask)))

    def get_non_flow_value(self, value):
        if not (value and self.has_non_flowing_context) or not value.get_register().is_processor_context():
            return None
        return value.clear_bit_values(list(map(lambda x: int(x), self.flowing_context_register_mask)))

class RegisterValue:
    def __init__(self, register):
        self.register = register

    def clear_bit_values(self, mask):
        # Implement the logic to clear bit values based on the given mask.
        pass


# Usage
language = Language()  # Define your language class here
context = AbstractProgramContext(language)
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an interpretation, as some parts might need adjustments according to Python syntax and semantics.

Also, the `RegisterValue` class has been implemented with a placeholder method (`clear_bit_values`) which needs to be replaced based on your actual requirements.