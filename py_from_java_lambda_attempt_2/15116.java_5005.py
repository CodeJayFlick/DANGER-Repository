Here is the translation of the Java code to Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class RoomSchemaSql:
    """Customer Schema SQL Class."""
    
    CREATE_SCHEMA_SQL = """
        CREATE TABLE ROOMS (
            ID NUMBER,
            ROOM_TYPE VARCHAR(100),
            PRICE INT,
            BOOKED VARCHAR(100)
        )
    """

    DELETE_SCHEMA_SQL = "DROP TABLE IF EXISTS ROOMS"

    def __init__(self):
        pass
```

Note that Python does not have a direct equivalent to Java's `public` and `private` access modifiers. In Python, everything is public by default unless you use the double underscore (`__`) prefix for private variables or methods.