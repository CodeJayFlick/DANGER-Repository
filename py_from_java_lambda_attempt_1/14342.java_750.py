Here is the translation of the Java code to Python:

```Python
import pymongo

class MongoBank:
    DEFAULT_DB = "lotteryDB"
    DEFAULT_ACCOUNTS_COLLECTION = "accounts"

    def __init__(self):
        self.connect()

    def connect(self, db_name=DEFAULT_DB, accounts_collection_name=DEFAULT_ACCOUNTS_COLLECTION):
        if hasattr(self, 'mongo_client'):
            self.mongo_client.close()
        self.mongo_client = pymongo.MongoClient(System.getProperty("mongo-host"), int(System.getProperty("mongo-port")))
        self.database = self.mongo_client[db_name]
        self.accounts_collection = self.database[accounts_collection_name]

    @property
    def mongo_client(self):
        return self._mongo_client

    @mongo_client.setter
    def mongo_client(self, value):
        self._mongo_client = value

    @property
    def database(self):
        return self._database

    @database.setter
    def database(self, value):
        self._database = value

    @property
    def accounts_collection(self):
        return self._accounts_collection

    @accounts_collection.setter
    def accounts_collection(self, value):
        self._accounts_collection = value


    def set_funds(self, bank_account: str, amount: int) -> None:
        search = {"_id": bank_account}
        update = {"$set": {"funds": amount}}
        options = {"upsert": True}
        self.accounts_collection.update_one(search, update, options)


    def get_funds(self, bank_account: str) -> int:
        try:
            return list(self.accounts_collection.find({"_id": bank_account}, {"funds": 1}))[0]["funds"]
        except IndexError:
            return 0


    def transfer_funds(self, amount: int, source_account: str, destination_account: str) -> bool:
        if self.get_funds(source_account) < amount:
            return False
        else:
            dest_funds = self.get_funds(destination_account)
            self.set_funds(source_account, self.get_funds(source_account) - amount)
            self.set_funds(destination_account, dest_funds + amount)
            return True

```

Note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by name and signature in Python.

Also note that the MongoDB operations are performed using PyMongo library which needs to be installed separately (`pip install pymongo`).