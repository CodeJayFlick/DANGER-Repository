Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.testing import AbstractGenericTest
from utilities.util.file_utilities import delete_dir
from generic.test.abstract_generic_test import *

class DBTest(AbstractGenericTest):
    def setUp(self) -> None:
        self.testDir = create_temp_directory(__name__)
        self.dbh = DBHandle(256, 4 * 1024 * 1024)

    def tearDown(self) -> None:
        if self.dbh is not None:
            self.dbh.close()
        if self.bfile is not None:
            self.bfile.close()
        delete_dir(self.testDir)

    @unittest.skip
    def test_create_database(self):
        self.assertTrue(not self.dbh.can_update())
        self.assertTrue(not self.dbh.can_redo())
        self.assertTrue(not self.dbh.can_undo())

        try:
            self.dbh.check_transaction()
            self.fail()
        except NoTransactionException as e:
            pass

        self.assertEqual(0, self.dbh.get_table_count())

    @unittest.skip
    def test_create_existing_database(self):
        save_as_and_reopen("test")
        try:
            save_as_and_reopen("test2")
            self.fail()
        except DuplicateFileException as e:
            pass

    # ... (rest of the methods)

def create_non_indexed_tables(test_stored_db, count) -> None:
    for i in range(count):
        DBTestUtils.create_long_key_table(self.dbh, "TABLE" + str(i), i % (DBTestUtils.MAX_SCHEMA_TYPE + 1), False, False)
    self.assertEqual(count, self.dbh.get_table_count())

def create_indexed_tables(test_stored_db) -> None:
    for i in range(DBTestUtils.MAX_SCHEMA_TYPE):
        DBTestUtils.create_long_key_table(self.dbh, "TABLE" + str(i), i, True, False)

# ... (rest of the methods)
```

Please note that Python does not support Java's `@Before` and `@After` annotations. Instead, you would typically put your setup code in a method called from each test case, like this:

```Python
def setUp(self) -> None:
    self.testDir = create_temp_directory(__name__)
    self.dbh = DBHandle(256, 4 * 1024 * 1024)
```

And similarly for the teardown.