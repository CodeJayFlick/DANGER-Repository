import pymongo

class MongoDBClient:
    def __init__(self):
        self.config = None
        self.managed_client = None
        self.global_pointers = None
        self.global_log = None
        self.commit_log = None
        self.key_lists = None

    def configure(self, config: dict) -> None:
        self.config = config

    def close(self) -> None:
        if self.managed_client is not None:
            try:
                self.managed_client.close()
            finally:
                self.managed_client = None

    def initialize(self) -> None:
        client_settings = pymongo.MongoClientSettings.from_uri(
            self.config.get("connection_string")
        )
        self.managed_client = pymongo.MongoClients.create(client_settings)

        database_name = self.config["database_name"]
        if not database_name:
            raise ValueError("Database name must be set")

        database = self.managed_client[database_name]
        self.global_pointers = database["global_pointer"]
        self.global_log = database["global_log"]
        self.commit_log = database["commit_log"]
        self.key_lists = database["key_list"]

    def get_global_pointers(self) -> pymongo.collection.Collection:
        return self.global_pointers

    def get_global_log(self) -> pymongo.collection.Collection:
        return self.global_log

    def get_commit_log(self) -> pymongo.collection.Collection:
        return self.commit_log

    def get_key_lists(self) -> pymongo.collection.Collection:
        return self.key_lists
