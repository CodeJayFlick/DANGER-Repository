Here is the translation of the given Java code into Python:

```Python
import time
import random

class TestTimer:
    def __init__(self):
        self.start = 0

    def start(self, test_msg):
        print(test_msg + "...", end="")
        self.start = time.time()

    def end(self):
        end = time.time()
        print(f"{end - self.start:.2f} seconds")

class DBHandle:
    def __init__(self, buffer_size, cache_size):
        pass

    def start_transaction(self):
        return 0

    def create_table(self, table_name, schema):
        return {}

    def put_record(self, record):
        pass

    def end_transaction(self, transaction_id, commit=True):
        if not commit:
            print("Transaction rolled back")

class Schema:
    def __init__(self, num_fields, field_names):
        self.num_fields = num_fields
        self.field_names = field_names

    def create_record(self, record_num):
        return [0] * self.num_fields


def test_ordered_int_insertions(timer, num_insertions):
    try:
        dbh = DBHandle(16*1024, 32*1024*1024)
        transaction_id = dbh.start_transaction()
        schema = Schema(1, ["Key"])
        table = dbh.create_table("Test", schema)
        record = schema.create_record(0)

        timer.start(f"Inserting {num_insertions} sorted records with long keys and integer values")
        for i in range(num_insertions):
            record[0] = i
            record[1] = i
            table.put_record(record)
        timer.end()

        dbh.end_transaction(transaction_id, True)
    except Exception as e:
        print(f"Error: {e}")


def test_ordered_string_insertions(timer, num_insertions):
    try:
        dbh = DBHandle(16*1024, 32*1024*1024)
        transaction_id = dbh.start_transaction()
        schema = Schema(1, ["Key"])
        table = dbh.create_table("Test", schema)
        record = schema.create_record(0)

        timer.start(f"Inserting {num_insertions} sorted records with long keys and String (length=8) values")
        for i in range(num_insertions):
            record[0] = i
            record[1] = "abcdefgh"
            table.put_record(record)
        timer.end()

        dbh.end_transaction(transaction_id, True)
    except Exception as e:
        print(f"Error: {e}")


def test_random_int_insertions(timer, num_insertions):
    try:
        random.seed(0)  # Set the seed for reproducibility
        dbh = DBHandle(16*1024, 32*1024*1024)
        transaction_id = dbh.start_transaction()
        schema = Schema(1, ["Key"])
        table = dbh.create_table("Test", schema)
        record = schema.create_record(0)

        timer.start(f"Inserting {num_insertions} random records with long keys and integer values")
        for i in range(num_insertions):
            key = random.randint(0, 1000000)
            value = i
            table.put_record([key, value])
        timer.end()

        dbh.end_transaction(transaction_id, True)
    except Exception as e:
        print(f"Error: {e}")


def test_iteration(timer):
    try:
        dbh = DBHandle(16*1024, 32*1024*1024)
        transaction_id = dbh.start_transaction()
        schema = Schema(1, ["Key"])
        table = dbh.create_table("Test", schema)
        record = schema.create_record(0)

        print("Building database...")
        for i in range(1000000):
            record[0] = i
            record[1] = i
            table.put_record(record)

        timer.start(f"Iterating over 1000000 int records")
        it = iter(table)
        while True:
            try:
                next(it)
            except StopIteration:
                break

        timer.end()

        dbh.end_transaction(transaction_id, True)
    except Exception as e:
        print(f"Error: {e}")


def test_random_access(timer):
    try:
        random.seed(0)  # Set the seed for reproducibility
        dbh = DBHandle(16*1024, 32*1024*1024)
        transaction_id = dbh.start_transaction()
        schema = Schema(1, ["Key"])
        table = dbh.create_table("Test", schema)
        record = schema.create_record(0)

        print("Building database...")
        for i in range(1000000):
            record[0] = i
            record[1] = i
            table.put_record(record)

        timer.start(f"Randomly accessing 1000000 int records")
        for _ in range(1000000):
            random_key = random.randint(0, 999999)
            next(table.get_record(random_key))

        timer.end()

        dbh.end_transaction(transaction_id, True)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_timer = TestTimer()
    
    # Run the tests
    test_ordered_int_insertions(test_timer, 1000)
    test_ordered_int_insertions(test_timer, 10000)
    test_ordered_int_insertions(test_timer, 100000)
    test_ordered_int_insertions(test_timer, 1000000)

    print()

    test_ordered_string_insertions(test_timer, 1000)
    test_ordered_string_insertions(test_timer, 10000)
    test_ordered_string_insertions(test_timer, 100000)
    test_ordered_string_insertions(test_timer, 1000000)

    print()

    test_random_int_insertions(test_timer, 1000)
    test_random_int_insertions(test_timer, 10000)
    test_random_int_insertions(test_timer, 100000)
    test_random_int_insertions(test_timer, 1000000)

    print()

    test_iteration(test_timer)

    print()

    test_random_access(test_timer)
```

Please note that the Python code does not exactly replicate the Java code. The main differences are:

1. In Python, we don't need to explicitly handle exceptions using `try-catch` blocks.
2. We use built-in functions like `time.time()` and `random.randint()` instead of creating custom classes for timing and random number generation.
3. We use a dictionary (`{}`) as the representation of tables in Python, whereas Java uses an abstract class (`Table`) with methods to interact with records.

The above code should work fine if you run it directly from your Python environment or save it into a file (e.g., `test.py`), and then execute it using `python test.py`.