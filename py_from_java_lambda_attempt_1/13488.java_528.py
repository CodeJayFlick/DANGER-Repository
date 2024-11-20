Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra.app.util.dialog import CheckoutDialog
from ghidra.framework.model import DomainFile
from ghidra.framework.remote import User
from ghidra.test.frontend_tool import FrontEndTestEnv
from ghidra.util.invalid_name_exception import InvalidNameException

class VersionControlScreenShots(unittest.TestCase):

    def test_add_to_version_control_dialog(self):
        dialog = CheckoutDialog(True)
        dialog.set_current_file_name("WinHelloCpp.exe")
        tool.show_dialog(dialog)

        capture_dialog()

    def test_check_in_file(self):
        dialog = CheckoutDialog(False)
        dialog.set_current_file_name(FrontEndTestEnv.PROGRAM_A)
        dialog.set_keep_checkbox_enabled(True)
        run_swing(lambda: tool.show_dialog(dialog), False)

        d = wait_for_dialog_component(CheckoutDialog)
        capture_dialog(d)

    def test_undo_hijack(self):
        plugin = get_front_end_plugin()
        action = VersionControlUndoHijackAction(plugin)
        df = create_domain_file()
        hijack_list = [df]
        run_swing(lambda: TestUtils.invoke_instance_method("undo_hijack", action, List, hijack_list), False)

        d = wait_for_dialog_component(UndoActionDialog)
        capture_dialog(d)

    def test_undo_checkout_dialog(self):
        df = create_domain_file()
        modified_list = [df]
        plugin = get_front_end_plugin()
        action = VersionControlUndoCheckOutAction(plugin)
        run_swing(lambda: TestUtils.invoke_instance_method("undo_checkouts", action, List, modified_list), False)

        d = wait_for_dialog_component(UndoActionDialog)
        capture_dialog(d)

    def test_checkout_file(self):
        user = User("User-1", 1)
        df = create_domain_file()
        dialog = CheckoutDialog(df, user)
        run_swing(lambda: dialog.show_dialog(), False)

        d = wait_for_dialog_component(CheckoutDialog)
        capture_dialog(d)

    def test_view_checkouts(self):
        try:
            user = User("User-1", 0)
            df = create_domain_file()

            checkouts = [
                ItemCheckoutStatus(1, CheckoutType.NORMAL, "User-1", 1, int(time.time()), "host1::/path1/TestRepo"),
                ItemCheckoutStatus(1, CheckoutType.EXCLUSIVE, "User-1", 1, int(time.time()), "host1::/path2/TestRepo")
            ]

            dialog = CheckoutsDialog(tool, user, df, checkouts)
            tool.show_dialog(dialog)

            d = wait_for_dialog_component("View Checkouts for " + FrontEndTestEnv.PROGRAM_A)
            capture_dialog(d)
        except Exception as e:
            print(f"Error: {e}")

    def test_version_history(self):
        try:
            df = create_domain_file()
            dialog = VersionHistoryDialog(df)
            run_swing(lambda: tool.show_dialog(dialog), False)

            d = wait_for_dialog_component(VersionHistoryDialog)
            capture_dialog(d)
        except Exception as e:
            print(f"Error: {e}")

    def get_front_end_plugin(self):
        fe_tool = env.show_frontend_tool()
        plugin = getInstanceField("plugin", fe_tool)
        return plugin

    def create_domain_file(self):
        root = TestDummyDomainFolder(None, "Project")
        df = TestDummyDomainFile(root, "Program_A")

        class DomainFile:
            @property
            def setName(self, new_name: str) -> 'DomainFile':
                # stubbed to prevent exception from dummy
                return self

            @property
            def getVersionHistory(self):
                time = int(time.time())
                user = "User-1"
                versions = [
                    Version(1, time - 200000, user, "Comment 1"),
                    Version(2, time - 100000, user, "Comment 2"),
                    Version(3, time, user, "Comment 3")
                ]
                return versions

        return df
```

Note: The Python code is not a direct translation of the Java code. It's an equivalent implementation in Python.