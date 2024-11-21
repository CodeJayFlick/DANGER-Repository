Here is the equivalent Python code:

```Python
import unittest
from pymongo import MongoClient

class MongoBankTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.TEST_DB = "lotteryDBTest"
        cls.TEST_ACCOUNTS_COLLECTION = "testAccounts"

    def setUp(self):
        client = MongoClient("mongodb://localhost:27017/")
        db = client[self.TEST_DB]
        collection_name = self.TEST_ACCOUNTS_COLLECTION
        if collection_name in db.list_collection_names():
            db.drop_collection(collection_name)
        client.close()
        self.mongo_bank = MongoBank(self.TEST_DB, self.TEST_ACCOUNTS_COLLECTION)

    def test_setup(self):
        self.assertEqual(0, len(list(self.mongo_bank.get_accounts_collection().find())))

    def test_fund_transfers(self):
        initial_balance = 0
        self.assertEqual(initial_balance, self.mongo_bank.get_funds("000-000"))
        self.mongo_bank.set_funds("000-000", 10)
        self.assertEqual(10, self.mongo_bank.get_funds("000-000"))
        self.assertEqual(initial_balance, self.mongo_bank.get_funds("111-111"))
        self.mongo_bank.transfer_funds(9, "000-000", "111-111")
        self.assertEqual(1, self.mongo_bank.get_funds("000-000"))
        self.assertEqual(9, self.mongo_bank.get_funds("111-111"))

if __name__ == '__main__':
    unittest.main()
```

Note: This Python code assumes that you have a `MongoBank` class with methods like `get_accounts_collection`, `set_funds`, and `transfer_funds`. You would need to implement these methods in your own `MongoBank` class.