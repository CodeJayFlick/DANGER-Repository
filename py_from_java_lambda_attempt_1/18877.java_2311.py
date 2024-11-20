Here is the translation of the given Java code into Python:

```Python
class TableReference:
    ILLEGAL_TABLE_REFERENCE_MESSAGE = "Illegal table reference: {}"

def from_contents_key_test_cases():
    return [
        {"name": "simple_name", "expected_name": "simple_name", "expected_reference": None, "expected_hash": None, "expected_timestamp": None},
        {"name": "`simple_name@ref`", "expected_name": "simple_name", "expected_reference": "ref", "expected_hash": None, "expected_timestamp": None},
        {"name": "`simple_name@ref#12345678abcdef12345678abcdef`", "expected_name": "simple_name", "expected_reference": "ref", "expected_hash": "12345678abcdef12345678abcdef", "expected_timestamp": None},
        {"name": "`simple_name#12345678abcdef12345678abcdef`", "expected_name": "simple_name", "expected_reference": None, "expected_hash": "12345678abcdef12345678abcdef", "expected_timestamp": None},
        {"name": "`simple_name@ref#2020-12-24`", "expected_name": "simple_name", "expected_reference": "ref", "expected_hash": None, "expected_timestamp": "2020-12-24"},
    ]

def test_from_contents_key(name, expected_name, expected_reference, expected_hash, expected_timestamp):
    tr = TableReference.parse(name)
    assert tr.name == expected_name
    if expected_reference is not None:
        assert tr.has_reference and tr.reference == expected_reference
    else:
        assert not tr.has_reference and tr.reference is None

    if expected_hash is not None:
        assert tr.has_hash and tr.hash == expected_hash
    else:
        assert not tr.has_hash and tr.hash is None

    if expected_timestamp is not None:
        assert tr.has_timestamp and tr.timestamp == expected_timestamp
    else:
        assert not tr.has_timestamp and tr.timestamp is None

def test_illegal_syntax(table_reference):
    try:
        TableReference.parse(table_reference)
    except ValueError as e:
        assert str(e) == f" Illegal table reference: {table_reference}"

def test_strange_characters():
    branch = "bar"
    path = "/%"
    tr = TableReference.parse(path)
    assert tr.name == path
    assert not tr.has_reference and tr.reference is None
    assert not tr.has_timestamp and tr.timestamp is None

    tr = TableReference.parse(f"{path}@{branch}")
    assert tr.name == path
    assert branch == str(tr.reference) if tr.has_reference else None
    assert not tr.has_timestamp and tr.timestamp is None

def test_double_byte():
    branch = "bar"
    path = "/%国"
    tr = TableReference.parse(path)
    assert tr.name == path
    assert not tr.has_reference and tr.reference is None
    assert not tr.has_timestamp and tr.timestamp is None

    tr = TableReference.parse(f"{path}@{branch}")
    assert tr.name == path
    assert branch == str(tr.reference) if tr.has_reference else None
    assert not tr.has_timestamp and tr.timestamp is None

def test_whitespace():
    branch = "bar"
    path = "foo "
    tr = TableReference.parse(path)
    assert tr.name == path
    assert not tr.has_reference and tr.reference is None
    assert not tr.has_timestamp and tr.timestamp is None

    tr = TableReference.parse(f"{path}@{branch}")
    assert tr.name == path
    assert branch == str(tr.reference) if tr.has_reference else None
    assert not tr.has_timestamp and tr.timestamp is None

if __name__ == "__main__":
    for case in from_contents_key_test_cases():
        test_from_contents_key(**case)

    test_illegal_syntax("foo@bar@boo")
    test_illegal_syntax("foo#baz#baa")
    test_illegal_syntax("foo@#baa")
    test_illegal_syntax("foo@#")
    test_illegal_syntax("foo@bar#")
    test_illegal_syntax("@bar#baz")
    test_illegal_syntax("@#baz")
    test_illegal_syntax("#baz")
    test_illegal_syntax("#")
    test_illegal_syntax("@")

    test_strange_characters()
    test_double_byte()
    test_whitespace()
```

This Python code does not use JUnit or any other testing framework. It uses simple assertions to verify the results of parsing table references.