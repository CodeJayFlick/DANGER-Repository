Here is the translation of the Java code into equivalent Python:

```Python
import time
from threading import Thread
from uuid import UUID

class AbstractGTest:
    def __init__(self):
        self.test_name = TestName()

    @property
    def test_directory_path(self):
        if not hasattr(self, 'test_directory_path'):
            self._create_test_directory()
        return self.test_directory_path

    def _create_test_directory(self):
        # In batch mode we rely on the fact that the test environment has been setup with a custom temp directory.
        if BATCH_MODE:
            self.test_directory_path = f"{System.getProperty('java.io.tmpdir')}/Ghidra_test_{UUID.random_uuid()}/{temp.data}"
        else:
            file_temp_dir = TestApplicationUtils.get_unique_temp_folder()
            self.test_directory_path = file_temp_dir.getAbsolutePath()

    def get_test_directory_path(self):
        return self.test_directory_path

    @staticmethod
    def random_int(min, max):
        distribution_length = (max - min) + 1
        random_value_in_range = time.random() * distribution_length
        random_int = int(random_value_in_range)
        value_in_range_with_offset = min + random_int
        return min if value_in_range_with_offset > max else value_in_range_with_offset

    @staticmethod
    def random_string(min, max):
        string_length = AbstractGTest.random_int(min, max)
        buffer = StringBuilder()
        for i in range(string_length):
            buffer.append(chr(AbstractGTest.random_int(65, 127)))
        return buffer.toString()

    @staticmethod
    def assert_arrays_equal_ordered(message, expected, actual):
        if not expected:
            assertNull(actual)
            return

        assertEquals(print_list_failure_message(message, expected, actual), len(expected), len(actual))
        for i in range(len(expected)):
            if not actual[i].equals(expected[i]):
                fail( print_list_failure_message(message, expected, actual) )

    @staticmethod
    def assert_arrays_equal_unordered(message, expected, actual):
        if not expected:
            assertNull(actual)
            return

        assertEquals(print_list_failure_message(message, expected, actual), len(expected), len(actual))
        for i in range(len(expected)):
            if not actual[i].equals(expected[i]):
                fail( print_list_failure_message(message, expected, actual) )

    @staticmethod
    def assert_contains_exactly(collection, *expected):
        set_expected = set(map(lambda x: str(x).encode('utf-8'), expected))
        set_actual = set(map(str.encode('utf-8'), collection))

        set_expected -= set_actual
        set_actual -= set(set_expected)

        if not actual_set:
            return

        fail("Collection did not contain expected results.\nExpected: " + str(expected) +
             "\nFound: " + str(collection))
    # Wait Methods

    @staticmethod
    def sleep(time_ms):
        start = time.time()
        try:
            Thread.sleep(time_ms)
        except InterruptedException as e:
            pass  # don't care

        end = time.time()
        return end - start

    @staticmethod
    def wait_for(latch, message="Timed-out waiting for CountDownLatch"):
        try:
            if not latch.await(DEFAULT_WAIT_TIMEOUT):
                raise AssertionError(message)
        except InterruptedException as e:
            fail("Interrupted waiting for CountDownLatch")

    # End Wait Methods