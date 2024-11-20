class FixedVirtualMemorySharedLibraryCommand:
    def __init__(self):
        pass

    @staticmethod
    def create_fixed_virtual_memory_shared_library_command(reader) -> 'FixedVirtualMemorySharedLibraryCommand':
        command = reader.get_factory().create(FixedVirtualMemorySharedLibraryCommand)
        command.init_fixed_virtual_memory_shared_library_command(reader)
        return command

    def init_fixed_virtual_memory_shared_library_command(self, reader):
        self.init_obsolete_command(reader)

    def get_command_name(self) -> str:
        return "fvmlib_command"

class ObsoleteCommand:
    @abstractmethod
    def init_obsolete_command(self, reader):
        pass


# Usage example:

reader = None  # Replace with your actual binary reader

command = FixedVirtualMemorySharedLibraryCommand.create_fixed_virtual_memory_shared_library_command(reader)
print(command.get_command_name())
