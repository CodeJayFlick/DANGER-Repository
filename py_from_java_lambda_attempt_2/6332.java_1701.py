Here is the translation of the given Java code into equivalent Python:

```Python
import os
from unittest import TestCase
from ghidra_test_framework import GhidraTestFramework
from ghidra.app.services import ProgramManagerService
from ghidra.program.model.data import DataTypeManager, SourceArchive
from ghidra.util.task import TaskMonitor

class ArchiveRemappedHeadedTest(GhidraTestFramework):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.plugin = self.env.get_plugin(DataTypeManagerPlugin)
        self.service = self.tool.get_service(ProgramManagerService)

        # Create windows_ VS9 archive copy before DataTypeManagerHandler initializes 
        # static list of known archives
        win32_archive_dir = os.path.join(self.env.get_module_data_subdirectory("Base", "typeinfo/win32"), "")
        vs12_archive_file = os.path.join(win32_archive_dir, "windows_vs12_32.gdt")
        vs9_archive_file = os.path.join(win32_archive_dir, "windows_VS9.gdt")

        if not os.path.exists(vs9_archive_file):
            FileUtilities.copy_file(os.path.join(win32_archive_dir, "windows_vs12_32.gdt"), vs9_archive_file)

    def tearDown(self):
        self.env.dispose()

    def test_get_remapped_archive(self):
        # Open VS9 archive
        dtm = self.service.open_data_type_archive("windows_VS9")
        assert dtm is not None

        try:
            self.assertEqual(dtm.get_name(), "windows_VS9")
        finally:
            close(dtm)

    def test_get_program_remapped_archive(self):
        # Add datatype from vs9 archive into program
        dtm = self.service.open_data_type_archive("windows_VS9")

        if not os.path.exists(vs9_archive_file):
            FileUtilities.copy_file(os.path.join(win32_archive_dir, "windows_vs12_32.gdt"), vs9_archive_file)

    def close(self, dmt):
        run_swing(lambda: get_archive(dtm).close())

class TestEnv:
    def __init__(self):
        self.tool = None
        self.plugin = None

    def get_tool(self):
        return self.tool

    def get_plugin(self, plugin_name):
        if not hasattr(self, 'plugin'):
            self.plugin = PluginTool()
        return getattr(self.plugin, plugin_name)

class ProgramManagerService:
    pass

class DataTypeManagerPlugin:
    pass
```

Please note that this is a direct translation of the given Java code into equivalent Python. It may require some modifications to work correctly in your specific environment.