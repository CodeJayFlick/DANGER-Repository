class CompositeDBAdapter:
    COMPOSITE_TABLE_NAME = "Composite Data Types"
    COMPOSITE_SCHEMA = None  # This will be set later based on version
    FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION = 6

    def __init__(self, handle):
        self.handle = handle
        if not hasattr(self, 'COMPOSITE_SCHEMA'):
            raise Exception("Schema is not defined")

    @property
    def flex_array_migration_required(self):
        return self._flex_array_migration_required

    @flex_array_migration_required.setter
    def flex_array_migration_required(self, value):
        self._flex_array_migration_required = value

    def get_adapter(open_mode, monitor):
        try:
            if open_mode == DBConstants.CREATE or open_mode == DBConstants.UPGRADE:
                return CompositeDBAdapterV5V6(handle, open_mode)
            else:
                return find_read_only_adapter()
        except VersionException as e:
            if not e.is_upgradable() or open_mode == DBConstants.UPDATE:
                raise
            adapter = find_read_only_adapter()
            if open_mode == DBConstants.UPGRADE:
                return upgrade(adapter, monitor)
            return adapter

    def is_flex_array_migration_required():
        return self._flex_array_migration_required

class CompositeDBAdapterV5V6(CompositeDBAdapter):
    V5V6_COMPOSITE_SCHEMA = None  # This will be set later based on version
    V5V6_ COMPOSITE_NAME_COL = 0
    V5V6_ COMPOSITE_COMMENT_COL = 1
    ...
