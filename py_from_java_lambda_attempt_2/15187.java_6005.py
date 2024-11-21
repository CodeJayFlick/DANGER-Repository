Here is a translation of the Java code into equivalent Python:

```Python
# Copyright Andreas Schildbach or original author(s)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import sqlite3

class AddressBookDatabase:
    _instance = None
    _database_name = "address_book"
    _migrations = []

    def __new__(cls):
        if cls._instance is None:
            synchronized(cls)  # Python doesn't have a direct equivalent for this, but we can use threading.Lock to achieve the same effect.
                if not hasattr(cls, 'initialized'):
                    cls.initialized = True
                    db_path = f"{cls._database_name}.db"
                    conn = sqlite3.connect(db_path)
                    c = conn.cursor()
                    c.execute('''
                        CREATE TABLE IF NOT EXISTS address_book (
                            address TEXT PRIMARY KEY,
                            label TEXT
                        )
                    ''')
                    conn.commit()
                    cls._instance = conn

        return super().__new__(cls)

    @classmethod
    def get_database(cls, context):
        if not hasattr(AddressBookDatabase, 'initialized'):
            AddressBookDatabase.initialized = True
            db_path = f"{AddressBookDatabase._database_name}.db"
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            # Add migrations here

        return cls._instance

    @classmethod
    def migrate(cls):
        if not hasattr(AddressBookDatabase, 'initialized'):
            AddressBookDatabase.initialized = True
            db_path = f"{AddressBookDatabase._database_name}.db"
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            # Add migration SQL here

class Migration:
    def __init__(self, from_version, to_version):
        self.from_version = from_version
        self.to_version = to_version

    def migrate(self, database):
        pass  # Implement your migration logic here.

# Usage example:

address_book_db = AddressBookDatabase.get_database(None)
c = address_book_db.cursor()
c.execute("INSERT INTO address_book (address, label) VALUES ('new_address', 'New Label')")
```

Please note that Python doesn't have direct equivalents for Java's Room and SQLite. The above code uses the built-in sqlite3 module to interact with a database file.