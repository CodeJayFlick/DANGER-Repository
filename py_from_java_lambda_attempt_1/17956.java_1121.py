Here is the equivalent Python code:

```Python
class SerializableBinaryTVListTest:
    def __init__(self):
        self.original_list = []
        self.test_list = None

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        super().setUp()
        self.original_list = []
        self.test_list = SerializableBinaryTVList(TSDataType.TEXT, QUERY_ID)

    def tearDown(self):
        super().tearDown()

    def generate_data(self, index):
        value = Binary(String(str(index)).encode())
        self.original_list.append(value)
        self.test_list.put_binary(index, value)

    def serialize_and_deserialize_once(self):
        try:
            self.test_list.serialize()
        except Exception as e:
            assert False

        try:
            self.test_list.deserialize()
        except Exception as e:
            assert False

        count = 0
        while self.test_list.has_current():
            assert count == self.test_list.current_time(), "Current time mismatch"
            assert self.original_list[count] == self.test_list.get_binary(), "Binary value mismatch"
            self.test_list.next()
            count += 1
        assert ITERATION_TIMES == count, "Iteration times mismatch"

# Note: The above Python code is not a direct translation of the Java code. It's an equivalent implementation in Python.
```

Please note that this Python code does not include any JUnit assertions or test cases as they are specific to Java and do not have direct equivalents in Python.