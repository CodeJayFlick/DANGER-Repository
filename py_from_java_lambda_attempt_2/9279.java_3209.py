Here is the translation of the Java code into Python:

```Python
import random

class TableTest:
    def __init__(self):
        self.fixed_size_schema_fields = [LongField.INSTANCE, IntField.INSTANCE, ShortField.INSTANCE, FixedField10.INSTANCE]
        self.variable_size_schema_fields = [StringField.INSTANCE]

        self.fixed_size_schema_column_names = ["Long1", "Int2", "Short3", "Fixed4"]
        self.variable_size_schema_column_names = ["String"]

    def setUp(self):
        pass

    @staticmethod
    def get_first_record_key_in_buffer(buffer_index, fixed_size):
        if fixed_size:
            return buffer_index * 100 - 10
        else:
            return buffer_index * 100 + 0

    @staticmethod
    def get_invalid_record_key_before_buffer(buffer_index, fixed_size):
        if fixed_size:
            return get_first_record_key_in_buffer(buffer_index, fixed_size) - 1
        else:
            return get_first_record_key_in_buffer(buffer_index, fixed_size)

    @staticmethod
    def get_middle_record_key_in_buffer(buffer_index, fixed_size):
        middle_record_offset = 5 * RECORD_KEY_SPACING
        if fixed_size:
            return get_first_record_key_in_buffer(buffer_index, fixed_size) + middle_record_offset
        else:
            return get_first_record_key_in_buffer(buffer_index, fixed_size)

    @staticmethod
    def get_last_record_key_in_buffer(buffer_index, fixed_size):
        last_record_offset = (100 - RECORD_KEY_SPACING)
        if fixed_size:
            return get_first_record_key_in_buffer(buffer_index, fixed_size) + last_record_offset
        else:
            return get_first_record_key_in_buffer(buffer_index, fixed_size)

    @staticmethod
    def get_invalid_key_before_buffer_ending(buffer_index, fixed_size):
        if fixed_size:
            return get_last_record_key_in_buffer(buffer_index, fixed_size) - 1
        else:
            return get_last_record_key_in_buffer(buffer_index, fixed_size)

    @staticmethod
    def get_invalid_key_after_buffer_ending(buffer_index, fixed_size):
        if fixed_size:
            return get_last_record_key_in_buffer(buffer_index, fixed_size) + 1
        else:
            return get_last_record_key_in_buffer(buffer_index, fixed_size)

    # Test method for testing the deletion of records in a table.
    def test_fixed_size_delete_records(self):
        start_keys = []
        end_keys = []

        for i in range(5):
            start_keys.append(get_first_record_key_in_buffer(i, True))
            end_keys.append(get_last_record_key_in_buffer(i, True))

        for start_key in start_keys:
            for end_key in end_keys:
                if start_key <= end_key:
                    initialize_database(True)
                    delete_range_and_verify(start_key, end_key)
                    close_database()

    # Test method for testing the deletion of records in a table.
    def test_variable_size_delete_records(self):
        start_keys = []
        end_keys = []

        for i in range(5):
            start_keys.append(get_first_record_key_in_buffer(i, False))
            end_keys.append(get_last_record_key_in_buffer(i, False))

        for start_key in start_keys:
            for end_key in end_keys:
                if start_key <= end_key:
                    initialize_database(False)
                    delete_range_and_verify(start_key, end_key)
                    close_database()

    # Method to generate a random string record.
    def generate_random_string_record(self):
        key = random.randint(0, 10000000)
        return {"key": key, "string_value": str(random.randint(1, 10))}

    # Initialize the database with records of fixed size or variable size.
    def initialize_database(self, fixed_size):
        if fixed_size:
            schema_fields = self.fixed_size_schema_fields
            column_names = self.fixed_size_schema_column_names
        else:
            schema_fields = self.variable_size_schema_fields
            column_names = self.variable_size_schema_column_names

        for i in range(10000):
            record_key = (i // 10) * RECORD_KEY_SPACING
            if fixed_size:
                rec = {"key": record_key, "long_value": random.randint(0, 100000), 
                       "int_value": random.randint(-100000, 100000), 
                       "short_value": random.randint(-32768, 32767)}
            else:
                rec = {"key": record_key, "string_value": str(random.randint(1, 10))}

    # Method to verify the range does not exist.
    def verify_range_does_not_exist(self):
        for i in range(start_key, end_key + 1):
            assert self.table.get_record(i) is None

    # Method to close the database connection.
    def close_database(self):
        pass
```

Note that this Python code doesn't have a direct equivalent of Java's `@Before` and `@Test` annotations. Instead, you would typically write test methods as instance methods in your class (like `test_fixed_size_delete_records`) or use a testing framework like unittest to define tests.

Also note that the original Java code has some parts removed for brevity, so this Python translation may not be exactly equivalent if those parts are restored.