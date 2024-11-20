import collections

class DbgListRegisterDescriptionsCommand:
    def __init__(self, manager):
        self.manager = manager
        self.list = []

    def complete(self, pending):
        return self.list

    def invoke(self):
        registers = self.manager.get_registers()
        descs = set(registers.get_all_descriptions())
        for desc in descs:
            self.list.append(desc)

class DebugRegisters:
    def get_all_descriptions(self):
        # implement this method to retrieve the descriptions
        pass

class DbgManagerImpl:
    def __init__(self, registers):
        self.registers = registers

    def get_registers(self):
        return self.registers

# Example usage:
manager = DbgManagerImpl(DebugRegisters())
command = DbgListRegisterDescriptionsCommand(manager)
command.invoke()
print(command.list)  # prints the list of register descriptions
