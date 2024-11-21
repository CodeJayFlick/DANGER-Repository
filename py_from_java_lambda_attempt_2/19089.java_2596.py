Here is the equivalent Python code:

```Python
class H2DatabaseAdapter:
    def __init__(self, config, db):
        pass  # No direct equivalent in Python for constructor with 'super' call.

    def database_sql_format_parameters(self) -> dict:
        return {
            "BLOB": "VARBINARY(390000)",
            "HASH": "VARCHAR",
            "KEY_PREFIX": "VARCHAR",
            "KEY": "VARCHAR",
            "NAMED_REF": "VARCHAR",
            "NAMED_REF_TYPE": "VARCHAR",
            "CONTENTS_ID": "VARCHAR",
            "INTEGER": "BIGINT"
        }
```

Note that Python does not have direct equivalent of Java's `ImmutableMap` and `@Override`. Also, the constructor in Python is defined using the `__init__` method.