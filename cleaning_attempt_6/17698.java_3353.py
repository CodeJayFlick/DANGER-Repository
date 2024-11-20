def test_only(func):
    def wrapper(*args, **kwargs):
        # Add any functionality here that should be executed before or after your function.
        result = func(*args, **kwargs)
        return result
    return wrapper

# Usage:
@test_only
def my_function():
    pass
