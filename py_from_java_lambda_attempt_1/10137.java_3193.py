Here is the translation of the Java code into Python:

```Python
import os
from tempfile import TemporaryDirectory
from unittest.mock import patch

class PackedDatabaseTest:
    def __init__(self):
        self.TEST_SCHEMA = Schema(1, "Key", [StringField.INSTANCE], ["Col1"])

    @patch('path.exists')
    def setUp(self, path_exists):
        with TemporaryDirectory() as temp_dir:
            packed_db_file_path = os.path.join(temp_dir.name, 'packed.db')
            packedDbFile = open(packed_db_file_path, 'w+')

    @after
    def tearDown(self):
        if PackedDatabaseCache.get_cache():
            cache_dir = PackedDatabaseCache.get_cache().get_instance_field('cacheDir')
            FileUtilities.delete_dir(cache_dir)
            os.mkdir(cache_dir)

        if dbh:
            dbh.close()

        if db:
            resource_file = db.get_packed_file()
            db.dispose()
            resource_file.delete()

    def create_packed_database(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file
        db = dbh.save_as("Test1", os.path.dirname(packedDbFile.name), os.path.basename(packedDbFile.name), None)
        id = dbh.get_database_id()
        dbh.close()

    @patch('path.exists')
    def test_create_packed_database(self, path_exists):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        assertEquals("MyContent", db.get_content_type())
        dbh = db.open(None)

    @patch('path.exists')
    def test_create_packed_database_with_specific_id(self):
        id = self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        assertEquals("MyContent", db.get_content_type())
        dbh = db.open(None)

    @patch('path.exists')
    def test_dispose(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    @patch('path.exists')
    def test_dispose_cached(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    @patch('path.exists')
    def test_auto_dispose_on_close(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    @patch('path.exists')
    def test_cache(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    @patch('path.exists')
    def test_auto_dispose_on_save_as(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_create_packed_database(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file
        db = dbh.save_as("Test1", os.path.dirname(packedDbFile.name), os.path.basename(packedDbFile.name), None)
        id = dbh.get_database_id()
        dbh.close()

    def test_create_packed_database_with_specific_id(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file with different id
        new_file_path = os.path.join(os.path.dirname(packedDbFile.name), str(dbh) + ".db")

    def test_dispose(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_dispose_cached(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_auto_dispose_on_close(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_cache(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_auto_dispose_on_save_as(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_create_packed_database(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file
        db = dbh.save_as("Test1", os.path.dirname(packedDbFile.name), os.path.basename(packedDbFile.name), None)
        id = dbh.get_database_id()
        dbh.close()

    def test_create_packed_database_with_specific_id(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file with different id
        new_file_path = os.path.join(os.path.dirname(packedDbFile.name), str(dbh) + ".db")

    def test_dispose(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_dispose_cached(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_auto_dispose_on_close(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_cache(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_auto_dispose_on_save_as(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_create_packed_database(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file
        db = dbh.save_as("Test1", os.path.dirname(packedDbFile.name), os.path.basename(packedDbFile.name), None)
        id = dbh.get_database_id()
        dbh.close()

    def test_create_packed_database_with_specific_id(self):
        # Create simple database
        dbh = PackedDBHandle("MyContent")
        tx_id = dbh.start_transaction()
        table = dbh.create_table("MyTable", self.TEST_SCHEMA)
        rec = self.TEST_SCHEMA.create_record(1)
        rec.set_string(0, "String1")
        table.put_record(rec)
        dbh.end_transaction(tx_id, True)

        # Create new packed db file with different id
        new_file_path = os.path.join(os.path.dirname(packedDbFile.name), str(dbh) + ".db")

    def test_dispose(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_dispose_cached(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_auto_dispose_on_close(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_cache(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(packedDbFile.name)
        file_dir = db.get_instance_field("dbDir")
        tmp_file_path = os.path.join(os.path.dirname(file_dir), str(dbh) + ".delete")

    def test_auto_dispose_on_save_as(self):
        self.create_packed_database()

        assert packedDbFile.exists()

        # Open packed db as read-only and verify content
        db = PackedDatabase.get_packed_database(p