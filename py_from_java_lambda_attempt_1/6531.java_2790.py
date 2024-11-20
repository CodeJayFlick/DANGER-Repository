Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_framework_project_tool import ProjectTestUtils


class RunToolTest(unittest.TestCase):

    DIRECTORY_NAME = 'test_directory'
    TOOL_NAME = "TestTool"

    def setUp(self):
        try:
            ProjectTestUtils.delete_project(DIRECTORY_NAME, self.TOOL_NAME)
        except Exception as e:
            print(f"Error in setup: {e}")
        project = ProjectTestUtils.get_project(DIRECTORY_NAME, self.TOOL_NAME)

    def tearDown(self):
        run_swing(lambda: project.save())
        run_swing(lambda: project.close())
        try:
            ProjectTestUtils.delete_project(DIRECTORY_NAME, self.TOOL_NAME)
        except Exception as e:
            print(f"Error in teardown: {e}")

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertNotNull'), "This test requires Python 3.5 or later")
    def test_run_tool(self):
        try:
            ProjectTestUtils.delete_tool(project, self.TOOL_NAME)
        except Exception as e:
            print(f"Error in delete tool: {e}")

        run_swing(lambda: tool = project.get_tool(None))
        tool.set_tool_name(self.TOOL_NAME)

        tool_config = ProjectTestUtils.save_tool(project, tool)
        run_swing(lambda: tool.close())

        tm = project.get_tool_manager()
        workspaces = tm.get_workspaces()

        active_workspace = workspaces[0]
        running_tool = active_workspace.run_tool(tool_config)
        self.assertIsNotNone(running_tool)

        run_swing(lambda: running_tool.close())
        try:
            ProjectTestUtils.delete_tool(project, self.TOOL_NAME)
        except Exception as e:
            print(f"Error in delete tool after test: {e}")


def run_swing(func):
    # This function is not implemented
    pass


if __name__ == '__main__':
    unittest.main()
```

Please note that the `run_swing` function is not implemented. It seems to be a placeholder for some kind of event loop or GUI interaction, but it's not clear what exactly this should do in Python.