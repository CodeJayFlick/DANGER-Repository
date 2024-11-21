import unittest
from threading import Thread
from time import sleep

class TestDataKeyModel:
    LONG_COL = 0
    STRING_COL = 1
    INT_COL = 2
    SHORT_COL = 3
    BYTE_COL = 4
    FLOAT_COL = 5
    DOUBLE_COL = 6

class SpyTextFilter:
    def __init__(self, text_filter, transformer, recorder):
        self.text_filter = text_filter
        self.transformer = transformer
        self.recorder = recorder

    def has_filtered(self):
        return True

    def reset(self):
        pass

class ThreadedTableTest(unittest.TestCase):

    SORT_SIZE_PATTERN = re.compile(".*\((\d+) rows\).*")

    def setUp(self):
        super().setUp()

    @before
    def test_setup(self):
        self.runSwing(lambda: self.model = TestDataKeyModel())

    def install_listeners(self):
        mouse_listeners = header.get_mouse_listeners()
        for l in mouse_listeners:
            if not isinstance(l, GTableMouseListener):
                continue

            header.remove_mouse_listener(l)
            header.add_mouse_listener(SpyMouseListenerWrapper(l, recorder))

        model.add_sort_listener(spy_load_listener)

    def test_failed(self, e):
        self.recorder.record("Test - testFailed()")
        sleep(0.1)
        self.dump_events()

    @after
    def tearDown(self):
        pass

    def create_test_model(self):
        return TestDataKeyModel()

    def assert_sort_size(self, size):
        message = self.spy_monitor.get_last_sort_message()
        matcher = SORT_SIZE_PATTERN.match(message)
        if not matcher:
            raise AssertionError("Message for sorting has changed--update the test")

        actual_size = int(matcher.group(1))
        assertEquals(size, actual_size)

    def filter(self, text):
        transformer = DefaultRowFilterTransformer(model, table.get_column_model())
        options = FilterOptions()
        factory = TextFilterFactory(options)
        self.spy_filter = SpyTextFilter(text_filter=text_factory.text_filter(transformer), recorder=recorder)

    @after
    def test_sorting_bytes(self):
        do_test_sorting(TestDataKeyModel.BYTE_COL)

    @after
    def test_sorting_shorts(self):
        do_test_sorting(TestDataKeyModel.SHORT_COL)

    @after
    def test_sorting_ints(self):
        do_test_sorting(TestDataKeyModel.INT_COL)

    @after
    def test_sorting_long(self):
        do_test_sorting(TestDataKeyModel.LONG_COL)

    @after
    def test_sorting_floats(self):
        do_test_sorting(TestDataKeyModel.FLOAT_ COL)

    @after
    def test_sorting_doubles(self):
        do_test_sorting(TestDataKeyModel.DOUBLE_ COL)
