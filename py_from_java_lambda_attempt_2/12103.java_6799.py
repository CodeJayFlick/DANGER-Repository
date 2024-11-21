Here is the translation of the Java code into Python:

```Python
class SymbolDatabaseAdapterV3:
    SYMBOL_VERSION = 3
    MIN_ADDRESS_OFFSET = 0
    MAX_ADDRESS_OFFSET = -1

    V3_SYMBOL_SCHEMA = {
        "Key": {"type": "long"},
        "Name": {"type": "string"},
        "Address": {"type": "long"},
        "Namespace": {"type": "long"},
        "Symbol Type": {"type": "int"},
        "String Data": {"type": "string"},
        "Flags": {"type": "byte"},
        "Locator Hash": {"type": "long"},
        "Primary": {"type": "boolean"},
        "Datatype": {"type": "long"},
        "Variable Offset": {"type": "int"}
    }

    def __init__(self, handle, addr_map, create=False):
        self.addr_map = addr_map
        if create:
            table_name = "SymbolTable"
            schema = V3_SYMBOL_SCHEMA
            symbol_table = handle.create_table(table_name, schema)
        else:
            try:
                symbol_table = handle.get_table("SymbolTable")
            except Exception as e:
                raise VersionException(f"Missing Table: {table_name}")
            if not isinstance(symbol_table.schema.version, int) or symbol_table.schema.version != SYMBOL_VERSION:
                version = symbol_table.schema.version
                if version < SYMBOL_VERSION:
                    raise VersionException(True)
                else:
                    raise VersionException(False)

    def create_symbol(self, name, address, namespace_id, symbol_type, string_data, data_type_id, var_offset, source, is_primary):
        next_id = self.symbol_table.get_key()
        if next_id == 0:
            next_id += 1
        return {
            "Key": {"value": next_id},
            "Name": {"value": name},
            "Address": {"value": address},
            "Namespace": {"value": namespace_id},
            "Symbol Type": {"value": symbol_type.id},
            "String Data": {"value": string_data},
            "Flags": {"value": source.ordinal()},
            "Locator Hash": {"value": self.compute_locator_hash(name, namespace_id, address)},
            "Primary": {"value": is_primary},
            "Datatype": {"value": data_type_id if data_type_id else None},
            "Variable Offset": {"value": var_offset}
        }

    def remove_symbol(self, symbol_id):
        try:
            self.symbol_table.delete_record(symbol_id)
        except Exception as e:
            raise IOException(f"Error removing symbol {symbol_id}")

    def has_symbol(self, address):
        key = self.addr_map.get_key(address, False)
        if key == self.addr_map.INVALID_ADDRESS_KEY and not isinstance(address, Address.NO_ADDRESS):
            return False
        try:
            return self.symbol_table.has_record({"value": key}, "Address")
        except Exception as e:
            raise IOException(f"Error checking for symbol {address}")

    def get_symbol_ids(self, address):
        key = self.addr_map.get_key(address, False)
        if key == self.addr_map.INVALID_ADDRESS_KEY and not isinstance(address, Address.NO_ADDRESS):
            return []
        try:
            return [record["Key"]["value"] for record in self.symbol_table.find_records({"value": key}, "Address")]
        except Exception as e:
            raise IOException(f"Error getting symbol IDs {address}")

    def get_symbol_record(self, symbol_id):
        try:
            return self.symbol_table.get_record(symbol_id)
        except Exception as e:
            raise IOException(f"Error getting symbol record {symbol_id}")

    def update_symbol_record(self, record):
        name = record["Name"]["value"]
        namespace_id = record["Namespace"]["value"]
        address_key = record["Address"]["value"]
        try:
            self.symbol_table.put_record(record)
        except Exception as e:
            raise IOException(f"Error updating symbol {name} with ID {namespace_id}")

    def get_symbols(self):
        return [record for record in self.symbol_table]

    def delete_external_entries(self, start_addr, end_addr):
        AddressRecordDeleter.delete_records(self.symbol_table, "Address", self.addr_map, start_addr, end_addr)

    def move_address(self, old_addr, new_addr):
        try:
            keys = [record["Key"]["value"] for record in self.symbol_table.find_records({"value": self.addr_map.get_key(old_addr, False)}, "Address")]
            for key in keys:
                rec = self.symbol_table.get_record(key)
                rec["Address"]["value"] = self.addr_map.get_key(new_addr, True)
                self.symbol_table.put_record(rec)
        except Exception as e:
            raise IOException(f"Error moving address {old_addr} to {new_addr}")

    def delete_address_range(self, start_addr, end_addr):
        try:
            return AddressRecordDeleter.delete_records(self.symbol_table, "Address", self.addr_map, start_addr, end_addr)
        except Exception as e:
            raise CancelledException(f"Error deleting address range from {start_addr} to {end_addr}")

    def get_symbols_by_namespace(self, namespace_id):
        try:
            return [record for record in self.symbol_table.index_iterator("Namespace", {"value": namespace_id}, {"value": namespace_id})]
        except Exception as e:
            raise IOException(f"Error getting symbols by namespace ID {namespace_id}")

    def get_symbols_by_name(self, name):
        try:
            return [record for record in self.symbol_table.index_iterator("Name", {"value": name}, {"value": name})]
        except Exception as e:
            raise IOException(f"Error getting symbols by name {name}")

    def compute_locator_hash(self, name, namespace_id, address_key):
        # implement the logic to compute locator hash
        pass

    @property
    def symbol_table(self):
        return self._symbol_table

    @symbol_table.setter
    def symbol_table(self, value):
        self._symbol_table = value


class VersionException(Exception):
    NEWER_VERSION = 1
    OLDER_VERSION = -1

    def __init__(self, version_diff=False, is_newer=True):
        if not isinstance(version_diff, bool) or (is_newer and version_diff == False) or (not is_newer and version_diff != True):
            raise ValueError("Invalid value for 'version_diff' parameter")
        super().__init__("Version mismatch" + (" newer" if is_newer else " older"))
```

Note that the `compute_locator_hash` method has been left as a placeholder, since it's not provided in the original Java code. You would need to implement this logic based on your specific requirements.

Also note that some methods have been modified slightly from their original form to better fit Python syntax and conventions.