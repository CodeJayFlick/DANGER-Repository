Here is the translation of the Java code into Python:

```Python
class ContextRegisterExtent:
    def __init__(self):
        self.context_registers = set()
        self.regs_to_values = {}

    def add_context_info(self, context_register_info_list):
        if not context_register_info_list or not context_register_info_list:
            return

        for creg_info in context_register_info_list:
            self.add_register_and_value(creg_info.get_context_register(), creg_info.get_value())

    def add_register_and_value(self, register, value):
        if register not in self.context_registers:
            self.context_registers.add(register)
            self.regs_to_values[register] = set()
        self.regs_to_values[register].add(value)

    def get_context_registers(self):
        return sorted(list(self.context_registers))

    def get_values_for_register(self, register):
        if not register or not self.regs_to_values.get(register):
            return []

        values_list = list(self.regs_to_values[register])
        return sorted(values_list)

    def __str__(self):
        if not self.context_registers:
            return ""

        sb = StringBuilder()
        for register in self.get_context_registers():
            sb.append(f"Register: {register}\n")
            sb.append("Values:\n")

            values = self.get_values_for_register(register)
            for i, value in enumerate(values):
                sb.append(str(value))
                if i < len(values) - 1:
                    sb.append(", ")
                else:
                    sb.append("\n\n")

        return str(sb)

class ContextRegisterInfo:
    def __init__(self, context_register, value):
        self.context_register = context_register
        self.value = value

    def get_context_register(self):
        return self.context_register

    def get_value(self):
        return self.value


# Example usage:

creg_info_list = [ContextRegisterInfo("reg1", 0), ContextRegisterInfo("reg2", 1),
                  ContextRegisterInfo("reg3", 2)]

extent = ContextRegisterExtent()
extent.add_context_info(creg_info_list)

print(extent)
```

Note that Python does not have direct equivalents for Java's `Set`, `Map`, and `List` classes. Instead, we use built-in types like sets (`set()`), dictionaries (`dict()`) and lists (`list()`). Also note the differences in syntax between Java and Python.