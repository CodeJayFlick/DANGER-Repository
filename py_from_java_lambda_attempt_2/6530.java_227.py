Here is the equivalent Python code:

```Python
import unittest
from ghidra_framework_project_tool import ProjectTestUtils


class DeleteToolTest(unittest.TestCase):

    PROJECT_DIRECTORY = AbstractGTest.get_test_directory_path()
    TOOL_NAME = "TestTool"

    def setUp(self):
        ProjectTestUtils.delete_project(PROJECT_DIRECTORY, self.TOOL_NAME)
        self.project = ProjectTestUtils.get_project(PROJECT_DIRECTORY, self.TOOL_NAME)

    def tearDown(self):
        self.project.close()
        ProjectTestUtils.delete_project(PROJECT_DIRECTORY, self.TOOL_NAME)

    def test_delete_tool(self):

        tool_chest = self.project.local_tool_chest

        # Make sure old tool instance does not exist
        if TOOL_NAME in tool_chest:
            del tool_chest[TOOL_NAME]

        # create a new running tool
        import threading
        run_thread = threading.Thread(target=lambda: setattr(self, 'running_tool', self.project.get_tool(None)))
        run_thread.start()
        run_thread.join()

        try:
            self.running_tool.set_tool_name(TOOL_NAME)

            # make sure tool config doesn't already exist in tool chest
            if TOOL_NAME in tool_chest:
                assert False, "Tool should not have been saved yet"

            # save it to the tool chest
            tool_template = self.running_tool.save_to_tool_template()
            tool_chest.add(tool_template)

            # now remove the tool config
            if not tool_chest.remove(TOOL_NAME):
                assert False, f"Delete Tool FAILED: remove returned false when removing {TOOL_NAME}"

            # verify the tool is no longer in the project toolchest
            if TOOL_NAME in tool_chest:
                assert False, f"Non-running tool: {TOOL_NAME} was not deleted as expected!!!"
        finally:
            run_thread = threading.Thread(target=lambda: self.running_tool.close())
            run_thread.start()
            run_thread.join()


if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the Java code to Python, and it may not be perfect.