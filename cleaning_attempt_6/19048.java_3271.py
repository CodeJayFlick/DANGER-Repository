# Copyright (C) 2020 Dremio

import logging

class MongoDatabaseAdapterFactory:
    NAME = "MongoDB"

    def get_name(self):
        return self.NAME

    def create_adapter(self, config: dict, client: object) -> object:
        from . import mongo_database_adapter
        adapter = mongo_database_adapter.MongoDatabaseAdapter(config, client)
        return adapter


# Example usage:
adapter_factory = MongoDatabaseAdapterFactory()
config = {"some_key": "some_value"}
client = {"some_client_object"}  # Replace with actual MongoDB client object
adapter = adapter_factory.create(config, client)

print(adapter.get_name())  # Output: "MongoDB"
