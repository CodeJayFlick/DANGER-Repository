Here is the translation of the given Java code into equivalent Python:

```Python
import rocksdb as r
from typing import List, Dict

class RocksDbInstance:
    def __init__(self):
        pass

    def configure(self, config: 'RocksDbConfig') -> None:
        self.db_path = config.get_db_path()

    def close(self) -> None:
        if hasattr(self, 'db'):
            try:
                self.db.close()
            finally:
                delattr(self, 'db')

    def initialize(self) -> None:
        if not hasattr(self, 'db') or self.db is None:
            if not self.db_path or len(self.db_path.strip()) == 0:
                raise ValueError("RocksDB instance missing dbPath option.")

            column_families = []
            column_families.append(r.DB().default_column_family_name)
            for cf in RocksDbInstance.CF_ALL:
                column_families.append(cf.encode('utf-8'))

            try:
                options = r.Options()
                options.create_if_missing = True
                options.create_missing_column_families = True

                db = r.TransactionDB(options, None, self.db_path, column_families)
                self.db = db

                for i in range(len(RocksDbInstance.CF_ALL)):
                    cf_name = RocksDbInstance.CF_ALL[i].encode('utf-8')
                    column_family_handles.append(db.get_cf_handle(cf_name))

            except r.RocksDBError as e:
                raise Exception("RocksDB failed to start", str(e))
```

Note: This Python code is not a direct translation of the given Java code. It's an equivalent implementation in Python, using the `rocksdb` library for interacting with RocksDB.

Also note that this code does not include all the methods and variables from the original Java code. The provided Java code seems to be part of a larger class hierarchy or framework, which is not easily translatable into Python without additional context.