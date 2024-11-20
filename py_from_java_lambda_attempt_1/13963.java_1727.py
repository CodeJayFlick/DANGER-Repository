Here is the translation of the Java code to Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CustomerSchemaSql:
    def __init__(self):
        pass

CREATE_SCHEMA_SQL = """
    CREATE TABLE CUSTOMERS (
        ID NUMBER,
        FNAME VARCHAR(100),
        LNAME VARCHAR(100)
    );
"""

DELETE_SCHEMA_SQL = "DROP TABLE CUSTOMERS"

# You can't make this class final in Python, but you could use a similar approach with a private constructor
```

Please note that the `CREATE_` and `DELETE_` SQL statements are defined as strings.