import unittest
from collections import defaultdict
from threading import Thread

class VersionControlCheckOutActionTest(unittest.TestCase):

    def setUp(self):
        self.spy_logger = SpyErrorLogger()
        self.spy_display = SpyErrorDisplay()

        self.root = TestRootDomainFolder()
        self.create_domain_files()

        Msg.set_error_logger(self.spy_logger)
        Msg.set_error_display(self.spy_display)

    @unittest.skip("Not implemented yet")
    def test_check_out_only_unversioned_files(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        self.checkout(action, self.unversioned)
        self.wait_for_tasks()
        self.assert_no_logged_messages()
        self.spy_display.assert_display_message("No versioned files")

    @unittest.skip("Not implemented yet")
    def test_check_out_only_versioned_and_not_checked_out_files_confirm_checkout(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        self.checkout(action, self.not_checked_out)
        self.confirm_checkout()
        self.wait_for_tasks()
        self.spy_logger.assert_log_message("Checkout completed", str(len(self.not_checked_out)))
        self.assert_no_displayed_messages()

    @unittest.skip("Not implemented yet")
    def test_check_out_only_versioned_and_not_checked_out_files_cancel_checkout(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        self.checkout(action, self.not_checked_out)
        self.cancel_checkout()
        self.wait_for_tasks()
        self.assert_no_logged_messages()
        self.assert_no_displayed_messages()

    @unittest.skip("Not implemented yet")
    def test_check_out_only_versioned_and_checked_out_files(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        self.checkout(action, self.checked_out)
        self.wait_for_tasks()
        self.assert_no_logged_messages()
        self.spy_display.assert_display_message("No versioned files")

    @unittest.skip("Not implemented yet")
    def test_check_out_only_versioned_files_that_fail_checkout(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        self.checkout(action, self.fail_to_checkout)
        self.confirm_checkout()
        self.wait_for_tasks()
        # this only happens when not using spies
        # self.spy_logger.assert_log_message("Multiple checkouts failed")
        self.spy_display.assert_display_message("Multiple checkouts failed")

    @unittest.skip("Not implemented yet")
    def test_check_out_mix_of_versioned_files_that_do_and_dont_fail_checkout(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        mixed = set(self.not_checked_out).union(set(self.fail_to_checkout))
        self.checkout(action, mixed)
        self.confirm_checkout()
        self.wait_for_tasks()
        # this only happens when not using spies
        # self.spy_logger.assert_log_message("Exclusive checkout failed")
        self.spy_display.assert_display_message("Exclusive checkout failed")

    @unittest.skip("Not implemented yet")
    def test_check_out_single_versioned_and_not_checked_out_file(self):
        tool = DummyPluginTool()
        action = VersionControlCheckOutAction("owner", tool)

        self.spy_logger.reset()
        self.spy_display.reset()

        file = set([CollectionUtils.any(self.not_checked_out)])
        self.checkout(action, file)
        self.wait_for_tasks()
        self.spy_logger.assert_log_message("Checkout completed 1")
        self.assert_no_displayed_messages()

    def run_swing(func):
        return func

    def wait_for_dialog_component(self, text):
        # implement this method
        pass

    def press_button_by_text(dialog, button_text):
        # implement this method
        pass

    def assert_no_logged_messages(self):
        self.assertTrue("Spy logger not empty: " + str(self.spy_logger), len(self.spy_logger) == 0)

    def create_domain_files(self):
        ordinal = 1
        end = ordinal + 3
        for _ in range(ordinal, end):
            test_file = TestDummyDomainFile(self.root, f"Program_{ordinal}", None)
            self.unversioned.add(test_file)

        end = ordinal + 3
        for _ in range(ordinal, end):
            test_file = TestDummyDomainFile(self.root, f"Program_{ordinal}", None)
            test_file.set_versioned()
            self.not_checked_out.add(test_file)

        end = ordinal + 3
        for _ in range(ordinal, end):
            test_file = CheckoutableDomainFile(self.root, f"Program_{ordinal}")
            test_file.set_versioned()
            test_file.set_unable_to_checkout()
            self.fail_to_checkout.add(test_file)

        end = ordinal + 3
        for _ in range(ordinal, end):
            test_file = TestDummyDomainFile(self.root, f"Program_{ordinal}", None)
            test_file.set_versioned()
            test_file.set_checked_out()
            self.checked_out.add(test_file)

    def run_swing(func, wait_for_tasks=False):
        return func

class SpyErrorLogger:
    def reset(self):
        pass

    # implement this method
    def assert_log_message(self, message1, message2, message3):
        pass

class SpyErrorDisplay:
    def reset(self):
        pass

    # implement this method
    def assert_display_message(self, message1, message2, message3):
        pass

class TestRootDomainFolder:
    def __init__(self):
        super().__init__(None, "Root")

    def create_file(self, name, obj, monitor=None):
        file = CheckoutableDomainFile(self, name)
        self.files.add(file)
        return file

class CheckoutableDomainFile:
    def __init__(self, parent, name):
        super().__init__(parent, name)

    def set_unable_to_checkout(self):
        pass

if __name__ == "__main__":
    unittest.main()
