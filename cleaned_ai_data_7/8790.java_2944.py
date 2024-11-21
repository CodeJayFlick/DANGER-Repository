class VTMatchSetDB:
    def __init__(self, record, session, db_handle, lock):
        super().__init__()
        self.match_set_record = record
        self.session = session
        self.db_handle = db_handle
        self.lock = lock

        self.match_cache = {}

    @classmethod
    def create_match_set_db(cls, record, session, db_handle, lock) -> 'VTMatchSetDB':
        match_set_db = cls(record, session, db_handle, lock)
        match_set_db.create_table_adapters(record.key)
        return match_set_db

    @classmethod
    def get_match_set_db(cls, record, session, db_handle, open_mode, monitor, lock) -> 'VTMatchSetDB':
        match_set_db = cls(record, session, db_handle, lock)
        match_set_db.get_table_adapters(record.key, open_mode, monitor)
        return match_set_db

    def create_table_adapters(self, table_id):
        self.match_table_adapter = VTMatchTableDBAdapter.create_adapter(self.db_handle, table_id)

    def get_table_adapters(self, table_id, open_mode, monitor):
        self.match_table_adapter = VTMatchTableDBAdapter.get_adapter(self.db_handle, table_id, open_mode, monitor)

    def db_error(self, exception):
        self.session.db_error(exception)

    @property
    def session(self) -> 'VTSession':
        return self._session

    @session.setter
    def session(self, value: 'VTSession'):
        self._session = value

    @property
    def match_count(self) -> int:
        return self.match_table_adapter.get_record_count()

    @property
    def program_correlator_info(self) -> 'ProgramCorrelatorInfo':
        if not hasattr(self, '_program_correlator_info') or not self._program_correlator_info:
            self._program_correlator_info = ProgramCorrelatorInfoImpl(self)
        return self._program_correlator_info

    def get_source_address_set(self) -> 'AddressSet':
        try:
            return self.session.get_source_address_set(self.match_set_record)
        except Exception as e:
            raise

    def get_destination_address_set(self) -> 'AddressSet':
        try:
            return self.session.get_destination_address_set(self.match_set_record)
        except Exception as e:
            raise

    def get_program_correlator_name(self) -> str:
        return self.match_set_record.get_string(VTMatchTableDBAdapter.CORRELATOR_NAME_COL.column())

    def get_program_correlator_class_name(self) -> str:
        return self.match_set_record.get_string(VTMatchTableDBAdapter.CORRELATOR_CLASS_ COL.column())

    @property
    def options(self):
        if not hasattr(self, '_options'):
            options_string = self.match_set_record.get_string(VTMatchTableDBAdapter.OPTIONS_COL.column())
            if options_string is None:
                return ToolOptions("EMPTY_OPTIONS_NAME")
            reader = StringReader(options_string)
            sax_builder = XmlUtilities.create_secure_sax_builder(False, False)

            try:
                root_element = sax_builder.build(reader).get_root_element()
                self._options = ToolOptions(root_element)
            except JDOMException as e:
                Msg.show_error(self, None, "Error Loading Key Bindings", "Unable to build XML data.", e)
            except IOException as e:
                Msg.show_error(self, None, "Error Loading Key Bindings", "Unable to build XML data.", e)

        return self._options

    def add_match(self, info: 'VTMatchInfo') -> 'VTMatch':
        association_manager = self.session.get_association_manager()
        association_db = association_manager.get_or_create_association_db(
            info.source_address,
            info.destination_address,
            info.association_type
        )
        tag = info.tag

        try:
            with self.lock:
                match_tag_db = self.session.get_or_create_match_tag_db(tag)
                record = self.match_table_adapter.insert_match_record(info, self, association_db, match_tag_db)
                return get_match_for_record(record)
        except Exception as e:
            raise
        finally:
            if new_match is not None:
                self.session.set_object_changed(VTChangeManager.DOCR_VT_MATCH_ADDED, new_match, null, new_match)

    def remove_match(self, match: 'VTMatch') -> bool:
        if not isinstance(match, VTMatchDB):
            return False

        try:
            with self.lock:
                record = self.match_table_adapter.get_record(match.key)
                deleted = self.match_cache.delete(record)
                if deleted and len(matches) == 1:
                    association_manager.remove_association(association)

                session.set_object_changed(VTChangeManager.DOCR_VT_MATCH_DELETED, match, null, new_match)
            return True
        except Exception as e:
            raise

    def get_id(self):
        return self.match_set_record.key

    @property
    def matches(self) -> list['VTMatch']:
        try:
            with self.lock:
                iterator = self.match_table_adapter.get_records()
                while iterator.has_next():
                    record = iterator.next()
                    match = get_match_for_record(record)
                    if match is not None:
                        yield match

        except Exception as e:
            raise
        finally:
            lock.release()

    def refresh(self):
        return True

    @property
    def is_invalid(self) -> bool:
        return self.session.get_match_set_record(key) is None

    def get_match_for_record(self, record: 'DBRecord') -> 'VTMatch':
        try:
            with self.lock:
                match = self.match_cache[record]
                if match is None:
                    match = VTMatchDB(self.match_cache, record, self)
                return match
        finally:
            lock.release()

    def get_match_record(self, key: int) -> 'DBRecord':
        try:
            return self.match_table_adapter.get_match_record(key)
        except Exception as e:
            raise

    @property
    def destination_program(self):
        return self.session.destination_program

    @destination_program.setter
    def destination_program(self, value):
        self._session = value

    @property
    def source_program(self) -> 'Program':
        return self.session.source_program

    @source_program.setter
    def source_program(self, value: 'Program'):
        self._session = value

    @property
    def association_manager(self) -> 'AssociationDatabaseManager':
        return self.session.association_manager_dbm

    @association_manager.setter
    def association_manager(self, value):
        self._session = value

    def invalidate_cache(self):
        with self.lock:
            try:
                self.match_cache.invalidate()
            finally:
                lock.release()

class VTMatchDB:
    pass

class ProgramCorrelatorInfoImpl:
    pass

class ToolOptions:
    pass
