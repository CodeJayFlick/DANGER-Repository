Here is the translation of the Java code into Python:

```Python
import unittest
from db import DBHandle, Schema, Table, StringField, LongField, ByteField, ShortField, IntField

class TestDBLongKeyChainedBufferUse(unittest.TestCase):

    def setUp(self):
        self.dbh = DBHandle(256, 4 * 1024 * 1024)
        big_length = ((self.dbh.get_buffer_size() - LongKeyRecordNode.RECORD_LEAF_HEADER_SIZE) >> 2) - 13
        self.big_length = big_length

    def tearDown(self):
        if self.dbh:
            self.dbh.close()

    def get_big_string(self, prefix, k):
        return f"{prefix}{k}"

    def get_small_string(self, prefix, k):
        return "small_" + f"{prefix}{k}"

    def fill_table_big_rec(self, count):
        tx_id = self.dbh.start_transaction()
        schema = Schema(0, "Enum ID", [
            StringField.INSTANCE,
            StringField.INSTANCE,
            LongField.INSTANCE,
            ByteField.INSTANCE,
            ShortField.INSTANCE,
            IntField.INSTANCE
        ], ["str1", "str2", "long", "byte", "short", "int"])
        table = self.dbh.create_table("TABLE1", schema)
        
        for k in range(0, 256, 2):
            rec = schema.create_record(k)
            rec.set_string(0, self.get_big_string("a", k))
            rec.set_string(1, self.get_small_string("b", k))
            rec.set_long_value(2, 0x2222222222222222L)
            rec.set_byte_value(3, 33)
            rec.set_short_value(4, 4444)
            rec.set_int_value(5, 55555555)
            table.put_record(rec)

        for k in range(1, 256, 2):
            rec = schema.create_record(k)
            rec.set_string(0, self.get_big_string("a", k))
            rec.set_string(1, self.get_small_string("b", k))
            rec.set_long_value(2, 0x2222222222222222L)
            rec.set_byte_value(3, 33)
            rec.set_short_value(4, 4444)
            rec.set_int_value(5, 55555555)
            table.put_record(rec)

        self.dbh.end_transaction(tx_id, True)
        return table

    def fill_table_small_rec(self, count):
        tx_id = self.dbh.start_transaction()
        schema = Schema(0, "Enum ID", [
            StringField.INSTANCE,
            StringField.INSTANCE,
            LongField.INSTANCE,
            ByteField.INSTANCE,
            ShortField.INSTANCE,
            IntField.INSTANCE
        ], ["str1", "str2", "long", "byte", "short", "int"])
        table = self.dbh.create_table("TABLE1", schema)
        
        for k in range(0, 256, 2):
            rec = schema.create_record(k)
            rec.set_string(0, self.get_small_string("a", k))
            rec.set_string(1, self.get_small_string("b", k))
            rec.set_long_value(2, 0x2222222222222222L)
            rec.set_byte_value(3, 33)
            rec.set_short_value(4, 4444)
            rec.set_int_value(5, 55555555)
            table.put_record(rec)

        for k in range(1, 256, 2):
            rec = schema.create_record(k)
            rec.set_string(0, self.get_small_string("a", k))
            rec.set_string(1, self.get_small_string("b", k))
            rec.set_long_value(2, 0x2222222222222222L)
            rec.set_byte_value(3, 33)
            rec.set_short_value(4, 4444)
            rec.set_int_value(5, 55555555)
            table.put_record(rec)

        self.dbh.end_transaction(tx_id, True)
        return table

    def test_node_fill_big(self):
        table = self.fill_table_big_rec(256)
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            assert rec.get_string(0) == f"a{k}"
            assert rec.get_string(1) == f"b{k}"
            #assert PrimitiveColumns(rec)

    def test_node_fill_small(self):
        table = self.fill_table_small_rec(256)
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            assert rec.get_string(0) == "small_a" + str(k)
            assert rec.get_string(1) == "small_b" + str(k)
            #assert PrimitiveColumns(rec)

    def test_node_update_big_to_small(self):
        table = self.fill_table_big_rec(256)
        
        tx_id = self.dbh.start_transaction()
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            rec.set_string(0, "small_a" + str(k))
            table.put_record(rec)

        for k in range(1, 256, 2):
            rec = table.get_record(k)
            rec.set_string(0, "small_a" + str(k))
            table.put_record(rec)

        self.dbh.end_transaction(tx_id, True)
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            assert rec.get_string(0) == "small_a" + str(k)
            assert rec.get_string(1) == f"b{k}"
            #assert PrimitiveColumns(rec)

    def test_node_update_big_to_really_big(self):
        table = self.fill_table_big_rec(256)
        
        tx_id = self.dbh.start_transaction()
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            rec.set_string(1, f"b{k}3")
            table.put_record(rec)

        for k in range(1, 256, 2):
            rec = table.get_record(k)
            rec.set_string(1, f"b{k}3")
            table.put_record(rec)

        self.dbh.end_transaction(tx_id, True)
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            assert rec.get_string(0) == f"a{k}"
            assert rec.get_string(1) == f"b{k}3"
            #assert PrimitiveColumns(rec)

    def test_node_update_really_big_to_really_big(self):
        self.test_node_update_big_to_really_big()
        
        table = self.dbh.get_table("TABLE1")
        
        tx_id = self.dbh.start_transaction()
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            rec.set_string(1, f"b{k}4")
            table.put_record(rec)

        for k in range(1, 256, 2):
            rec = table.get_record(k)
            rec.set_string(1, f"b{k}4")
            table.put_record(rec)

        self.dbh.end_transaction(tx_id, True)
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            assert rec.get_string(0) == f"a{k}"
            assert rec.get_string(1) == f"b{k}4"
            #assert PrimitiveColumns(rec)

    def test_node_update_small_to_big(self):
        table = self.fill_table_small_rec(256)
        
        tx_id = self.dbh.start_transaction()
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            rec.set_string(1, f"b{k}")
            table.put_record(rec)

        for k in range(1, 256, 2):
            rec = table.get_record(k)
            rec.set_string(1, f"b{k}")
            table.put_record(rec)

        self.dbh.end_transaction(tx_id, True)
        
        for k in range(0, 256, 2):
            rec = table.get_record(k)
            assert rec.get_string(0) == "small_a" + str(k)
            assert rec.get_string(1) == f"b{k}"
            #assert PrimitiveColumns(rec)

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python, and it may not be optimal or idiomatic.