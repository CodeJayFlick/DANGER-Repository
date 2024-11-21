import pymongo
from typing import Dict

class MongoTestResourceLifecycleManager:
    def __init__(self):
        self.mongo = FlapdoodleMongoTestConnectionProviderSource()

    def start(self) -> Dict[str, str]:
        try:
            self.mongo.start()
        except Exception as e:
            raise ValueError(str(e))

        config = self.mongo.get_connection_provider_config()
        return {
            "quarkus.mongodb.connection_string": config["connection_string"],
            "quarkus.mongodb.database": config["database_name"]
        }

    def stop(self):
        try:
            self.mongo.stop()
        except Exception as e:
            raise ValueError(str(e))
