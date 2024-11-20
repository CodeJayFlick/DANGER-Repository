Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_framework import *
from generic_test import *

class CreateWorkspaceTest(unittest.TestCase):

    def setUp(self):
        ProjectTestUtils.delete_project(DIRECTORY_NAME, PROJECT_NAME)
        self.project = ProjectTestUtils.get_project(DIRECTORY_NAME, PROJECT_NAME)

    def tearDown(self):
        run_swing(lambda: self.project.close())
        ProjectTestUtils.delete_project(DIRECTORY_NAME, PROJECT_NAME)

    def test_create_workspace(self):

        tool_manager = self.project.get_tool_manager()
        user_name = SystemUtilities.get_user_name()

        tool_manager.create_workspace(user_name)
        
        try:
            tool_manager.create_workspace(user_name)
            self.fail("Should have gotten DuplicateNameException for " + user_name)
        except DuplicateNameException as e:
            pass

        tool_manager.create_workspace(user_name + "(1)")
        tool_manager.create_workspace(user_name + "(2)")

        workspaces = tool_manager.get_workspaces()
        for wspace in workspaces:
            print("Found workspace " + wspace.name)

        self.assertEqual(4, len(workspaces))
        self.assertEqual("Workspace", workspaces[0].name)
        self.assertEqual(user_name, workspaces[1].name)
        self.assertEqual(user_name + "(1)", workspaces[2].name)
        self.assertEqual(user_name + "(2)", workspaces[3].name)

        tool_manager.remove_workspace(workspaces[2])  # 3rd workspace is user_name(1)

        workspaces = tool_manager.get_workspaces()
        self.assertEqual(3, len(workspaces))

        for wspace in workspaces:
            if wspace.name == user_name + "(1)":
                self.fail("Should have deleted workspace " + wspace.name)
        
        try:
            workspaces[0].name = user_name
            self.fail("DuplicateNameException expected")
        except DuplicateNameException as e:
            pass

        workspaces[1].name = "WORKSPACE-1"
        self.assertEqual("WORKSPACE-1", workspaces[1].name)

        set_workspace_active(workspaces[0])

        workspace = workspaces[0]
        run_swing(lambda: workspace.create_tool())
        
        running_tools = workspace.get_tools()
        self.assertEqual(1, len(running_tools))

        set_workspace_active(workspaces[1])
        running_tools = workspace.get_tools()

        self.project.save()

        run_swing(lambda: self.project.close())

        # now restore it
        run_swing(lambda:
            try:
                self.project = ProjectTestUtils.get_project(DIRECTORY_NAME, PROJECT_NAME)
            except LockException as e:
                e.print_stack_trace()
                self.fail()
            except IOException as e:
                e.print_stack_trace()
                self.fail())

        tool_manager = self.project.get_tool_manager()
        workspaces = tool_manager.get_workspaces()

        for wspace in workspaces:
            print("** Workspace " + wspace.name)

        self.assertEqual(3, len(workspaces))
        self.assertEqual("Workspace", workspaces[0].name)
        self.assertEqual("WORKSPACE-1", workspaces[1].name)
        self.assertEqual(user_name + "(2)", workspaces[2].name)

        self.assertEqual(workspaces[1], tool_manager.get_active_workspace())

    def set_workspace_active(self, workspace):
        run_swing(lambda: workspace.set_active())


if __name__ == "__main__":
    unittest.main()
```

Note that this code is not a direct translation of the Java code. It's more like an equivalent Python implementation with some adjustments to fit the Python syntax and semantics.