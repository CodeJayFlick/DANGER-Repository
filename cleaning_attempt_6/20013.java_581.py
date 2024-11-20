def not_null(*objects):
    for i in range(len(objects)):
        if objects[i] is None:
            raise ValueError(f"The {i+1} parameter must not be null")

def not_null(obj, name):
    if obj is None:
        raise ValueError(f"{name} must not be null")

def is_true(b, error):
    if not b:
        raise ValueError(error)

def is_false(b, error):
    if b:
        raise ValueError(error)

def not_or_empty(s, name):
    if s is None or len(str(s).strip()) == 0:
        raise ValueError(f"{name} must neither be null nor empty")

def not_or_empty(array, name):
    if array is None or len(array) == 0:
        raise ValueError(f"{name} must neither be null nor empty")

def not_or_empty(collection, name):
    if collection is None or len(list(collection)) == 0:
        raise ValueError(f"{name} must neither be null nor empty")

def not_empty(s, name):
    if s and len(str(s).strip()) == 0:
        raise ValueError(f"{name} must not be empty")

def not_empty(array, name):
    if len(array) == 0:
        raise ValueError(f"{name} must not be empty")
