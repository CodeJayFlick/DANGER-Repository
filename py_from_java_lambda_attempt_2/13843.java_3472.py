Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch, Mock
from bson.son import SON

class MongoDbTest(unittest.TestCase):
    ID = "123"
    NAME = "Some user"
    ADDITIONAL_INFO = "Some app Info"

    @patch('com.mongodb.client.MongoDatabase')
    def setUp(self, mock_db):
        self.db = mock_db()
        self.mongoDb = MongoDb()
        self.userAccount = UserAccount(ID, NAME, ADDITIONAL_INFO)

    def test_connect(self):
        assert not self.mongoDb.connect()

    def test_read_from_db(self):
        document = SON({self.ID: ID, self.NAME: NAME, 'additional_info': ADDITIONAL_INFO})
        mongo_collection = Mock()
        find_iterable = Mock()
        self.db.get_collection.return_value.find.return_value.to_list.return_value = [document]
        self.assertEqual(self.mongoDb.read_from_db(ID), self.userAccount)

    def test_write_to_db(self):
        mongo_collection = Mock()
        self.db.get_collection.return_value.insert_one.return_value = None
        assert not self.mongoDb.write_to_db(self.userAccount)

    def test_update_db(self):
        mongo_collection = Mock()
        self.db.get_collection.return_value.update_one.return_value = None
        assert not self.mongoDb.update_db(self.userAccount)

    def test_upsert_db(self):
        mongo_collection = Mock()
        self.db.get_collection.return_value.find_one_and_replace.return_value = None
        assert not self.mongoDb.upsert_db(self.userAccount)
```

Note: This code assumes that you have a `MongoDb` class and a `UserAccount` class in your Python program.