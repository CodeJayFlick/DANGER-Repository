class DBTraceContentHandler:
    TRACE_CONTENT_TYPE = "Trace"

    def create_file(self, fs, userfs, path, name, obj, monitor):
        if not isinstance(obj, DBTrace):
            raise IOException("Unsupported domain object: " + str(obj.__class__.__name__))
        return self.create_file_(obj, self.TRACE_CONTENT_TYPE, fs, path, name, monitor)

    def create_file_(self, trace_obj, content_type, fs, path, name, monitor):
        # Implementation of the method
        pass

    def get_immutable_object(self, item, consumer, version, min_change_version, monitor):
        if not isinstance(item, DatabaseItem):
            raise IOException("Unsupported domain object: " + str(item.__class__.__name__))
        db_item = item
        bf = None
        dbh = None
        trace_obj = None
        success = False
        try:
            bf = db_item.open(version, min_change_version)
            dbh = DBHandle(bf)
            open_mode = DBOpenMode.READ_ONLY if version == 0 else DBOpenMode.UPDATE
            trace_obj = DBTrace(dbh, open_mode, monitor, consumer)
            self.get_trace_change_set(trace_obj, bf)
            success = True
        except (VersionException, IOException, CancelledException) as e:
            raise e
        finally:
            if not success and trace_obj is not None:
                trace_obj.release(consumer)
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def get_read_only_object(self, item, version, ok_to_upgrade, consumer, monitor):
        if not isinstance(item, DatabaseItem):
            raise IOException("Unsupported domain object: " + str(item.__class__.__name__))
        db_item = item
        bf = None
        dbh = None
        trace_obj = None
        success = False
        try:
            bf = db_item.open(version)
            dbh = DBHandle(bf, ok_to_upgrade and DBOpenMode.UPGRADE or DBOpenMode.UPDATE, monitor)
            open_mode = DBOpenMode.READ_ONLY if version == 0 else (ok_to_upgrade and DBOpenMode.UPGRADE or DBOpenMode.UPDATE)
            trace_obj = DBTrace(dbh, open_mode, monitor, consumer)
            self.get_trace_change_set(trace_obj, bf)
            success = True
        except (VersionException, IOException, CancelledException) as e:
            raise e
        finally:
            if not success and trace_obj is not None:
                trace_obj.release(consumer)
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def get_domain_object(self, item, userfs, checkout_id, ok_to_upgrade, recover, consumer, monitor):
        if not isinstance(item, DatabaseItem):
            raise IOException("Unsupported domain object: " + str(item.__class__.__name__))
        db_item = item
        bf = None
        dbh = None
        trace_obj = None
        success = False
        try:
            bf = db_item.open_for_update(checkout_id)
            dbh = DBHandle(bf, recover and DBOpenMode.RECOVER or DBOpenMode.UPDATE, monitor)
            open_mode = ok_to_upgrade and DBOpenMode.UPGRADE or DBOpenMode.UPDATE
            trace_obj = DBTrace(dbh, open_mode, monitor, consumer)
            if checkout_id == FolderItem.DEFAULT_CHECKOUT_ID:
                self.get_trace_change_set(trace_obj, bf)
            if recover:
                self.recover_change_set(trace_obj, dbh)
                trace_obj.set_changed(True)
            success = True
        except (VersionException, IOException, CancelledException) as e:
            raise e
        finally:
            if not success and trace_obj is not None:
                trace_obj.release(consumer)
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def get_trace_change_set(self, trace_obj, bf):
        # Implementation of the method
        pass

    def recover_change_set(self, trace_obj, dbh):
        # Implementation of the method
        pass

    def get_domain_object_class(self):
        return DBTrace

    def get_content_type(self):
        return self.TRACE_CONTENT_TYPE

    def get_content_type_display_string(self):
        return "Trace"

    def default_tool_name(self):
        return "Debugger"  # TODO: Actually make this tool

    def icon(self):
        return Trace TRACE_ICON

    def is_private_content_type(self):
        return False
