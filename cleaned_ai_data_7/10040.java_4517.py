import unittest
from ghidra.util.default_error_logger import DefaultErrorLogger
from ghidra.util.exception.multiple_causes import MultipleCauses


class DockingErrorDisplayTest(unittest.TestCase):

    def setUp(self):
        self.display = None

    @unittest.skip("Not implemented yet")
    def testDefaultErrorDisplay_SingleException(self):
        exception = Exception("My test exception")
        report_exception(self.display, DefaultErrorLogger(), exception)
        assert_err_log_dialog()

    @unittest.skip("Not implemented yet")
    def testDefaultErrorDisplay_NestedException(self):
        nested_exception = Exception("My nested test exception")
        exception = Exception("My test exception", nested_exception)
        report_exception(self.display, DefaultErrorLogger(), exception)
        assert_err_log_dialog()

    @unittest.skip("Not implemented yet")
    def testDefaultErrorDisplay_MultipleAsynchronousExceptions(self):
        self.display = DockingErrorDisplay()
        logger = DefaultErrorLogger()
        exception = Exception("My test exception")
        report_exception(self.display, logger, exception)

        dialog = get_err_log_dialog()

        assert_exception_count(dialog, 1)
        report_exception(self.display, logger, NullPointerException("It is null!"))
        assert_exception_count(dialog, 2)
        report_exception(self.display, logger, NullPointerException("It is null!"))
        assert_exception_count(dialog, 3)

        self.assertEqual("Test Title (3 Errors)", dialog.get_title())
        close(dialog)

    @unittest.skip("Not implemented yet")
    def testMultipleCausesErrorDisplay(self):
        self.display = DockingErrorDisplay()
        logger = DefaultErrorLogger()

        first_cause = Exception("My test exception - first cause")
        multiple_caused_exception = MultipleCauses([first_cause])
        report_exception(self.display, logger, multiple_caused_exception)

        dialog = assert_err_log_expandable_dialog()
        assert_exception_count(dialog, 1)
        report_exception(self.display, logger, NullPointerException("It is null!"))
        assert_exception_count(dialog, 2)

    def assertExceptionCount(self, errDialog, n):
        actual = errDialog.getExceptionCount()
        self.assertEqual(n, actual)

    def assertErrLogExpandableDialog(self):
        w = waitForWindow(TEST_TITLE)
        self.assertIsNotNone(w)

        dialog = get_dialog_component_provider(w, ErrLogExpandableDialog)
        self.assertIsNotNone(dialog)
        return dialog

    def assertErrLogDialog(self):
        w = waitForWindow(TEST_TITLE)
        self.assertIsNotNone(w)

        errDialog = get_dialog_component_provider(w, ErrLogDialog)
        self.assertIsNotNone(errDialog)
        close(errDialog)

    def getErrLogExpandableDialog(self):
        w = waitForWindow(TEST_TITLE)
        self.assertIsNotNone(w)

        dialog = get_dialog_component_provider(w, ErrLogExpandableDialog)
        self.assertIsNotNone(dialog)
        return dialog

    def reportException(self, display, logger, throwable):
        run_swing(lambda: (logger.error(this, ">>>>>>>>>>>>>>> Expected Exception"),
                           display.displayErrorMessage(logger, this, None, TEST_TITLE,
                                                      "Test Message", throwable),
                           logger.error(this, "<<<<<<<<<<<<<<<< End Expected Exception")))

        wait_for_swing()

    def close(self, dialog):
        pass

if __name__ == "__main__":
    unittest.main()
