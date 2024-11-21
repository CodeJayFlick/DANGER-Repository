class PropertiesDBAdapterV0:
    def __init__(self, db_handle):
        self.properties_table = db_handle.get_table("PROPERTIES_TABLE_NAME")
        self.test_version(0)

    def get_records(self):
        return self.properties_table.iterator()

    def put_record(self, property_name, type, obj_class_name):
        rec = DBPropertyMapManager.PROPERTIES_SCHEMA.create_record(StringField(property_name))
        rec.set_byte_value(DBPropertyMapManager.PROPERTY_TYPE_COL, type)
        if type == DBPropertyMapManager.OBJECT_PROPERTY_TYPE:
            rec.set_string(DBPropertyMapManager.OBJECT_CLASS_COL, obj_class_name)

        self.properties_table.put_record(rec)

    def remove_record(self, property_name):
        self.properties_table.delete_record(StringField(property_name))

    def test_version(self, expected_version):
        if not hasattr(self, 'properties_table'):
            raise VersionException("Properties table not found")
        version_number = self.properties_table.get_schema().get_version()
        if version_number != expected_version:
            raise VersionException(f"Properties table: Expected Version {expected_version}, got {version_number}")
