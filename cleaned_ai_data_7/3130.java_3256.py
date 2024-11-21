import ghidra_app_factory as app_factory
from ghidra_framework import PluggableServiceRegistry
from ghidra_program_database import *

class FoundationInitializer:
    def run(self):
        registry = PluggableServiceRegistry()
        registry.register(ToolStateFactory, GhidraToolStateFactory())
        registry.register(GhidraDataFlavorHandlerService, GhidraDataFlavorHandlerService())
        registry.register(
            GhidraFileOpenDataFlavorHandlerService,
            GhidraFileOpenDataFlavorHandlerService(),
        )
        registry.register(DataTypeArchiveMergeManagerFactory, GhidraDataTypeArchiveMergeManagerFactory())
        registry.register(ProgramMultiUserMergeManagerFactory, GhidraProgramMultiUserMergeManagerFactory())

    def get_name(self):
        return "Base Module"

if __name__ == "__main__":
    initializer = FoundationInitializer()
    initializer.run()

print(initializer.get_name())
