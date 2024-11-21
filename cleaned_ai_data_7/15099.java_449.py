import threading
from datetime import datetime as dt
from calendar import monthrange

class Result:
    def __init__(self):
        self.date_list = []
        self.exception_list = []

def convert_dates_to_string(result: list) -> list:
    if not result or not result[0]:
        return None
    date_values = [f"{dt(dt.year, dt.month, day).strftime('%d.%m.%Y')}" for _, day in monthrange(2015, 11)]
    return date_values

def setup():
    callable_df = DateFormatCallable("dd/MM/yyyy", "15/12/2015")
    executor = threading.ThreadPool()
    futures = [executor.submit(callable_df) for _ in range(4)]

    results = []
    created_date_values = []

    try:
        for future in futures:
            result, exception_list = future.result(), None
            if not exception_list:
                date_list = convert_dates_to_string(result)
                created_date_values.append(date_list)

    except Exception as e:
        print(f"Setup failed: {e}")

def test_date_values():
    assert all(created_date_value == expected_date_values for created_date_value in created_date_values), "Test Date Values"

def test_counter_date_values():
    assert all(len(value) == 5 for value in created_date_values), "Test Counter Date Values"

def test_counter_exceptions():
    assert all(not result[1] for result in results), "Test Counter Exceptions"
