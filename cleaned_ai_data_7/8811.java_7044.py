class VTSessionContentHandler:
    ICON = ResourceManager().get_scaled_icon(ResourceManager().load_image("images/start-here_16.png"), 16, 16)

    CONTENT_TYPE = "VersionTracking"

    def create_file(self, fs, userfs, path, name, domain_object, monitor):
        if not isinstance(domain_object, VTSessionDB):
            raise IOException("Unsupported domain object: " + str(domain_object.__class__.__name__))
        return self.create_file((VTSessionDB)(domain_object), CONTENT_TYPE, fs, path, name, monitor)

    def get_change_set(self, versioned_folder_item, older_version, newer_version):
        return None

    def get_content_type(self):
        return CONTENT_TYPE

    def get_content_type_display_string(self):
        return "Version Tracking Session"

    def get_default_tool_name(self):
        return "Version Tracking"

    def get_domain_object(self, item, userfs, checkout_id, ok_to_upgrade, ok_to_recover, consumer, monitor):
        if not isinstance(item, DatabaseItem):
            raise IOException("Unsupported content type: " + str(item.__class__.__name__))
        try:
            db_item = (DatabaseItem)(item)
            bf = db_item.open_for_update(checkout_id)
            dbh = DBHandle(bf, ok_to_recover, monitor)
            success = False
            try:
                manager = VTSessionDB.get_vt_session(dbh, OpenMode.UPGRADE, consumer, monitor)
                success = True
                return manager
            finally:
                if not success:
                    dbh.close()
        except (VersionException, IOException):
            raise
        except CancelledException as e:
            raise e
        except Exception as e:
            Msg.error(self, "getDomainObject failed", e)
            msg = str(e).strip() or str(e.__class__.__name__)
            raise IOException("Open failed: " + msg)

    def get_domain_object_class(self):
        return VTSessionDB

    def get_icon(self):
        return ICON

    def get_immutable_object(self, item, consumer, version, min_change_version, monitor):
        if not isinstance(item, DatabaseItem):
            raise IOException("Unsupported content type: " + str(item.__class__.__name__))
        return self.get_read_only_object(item, -1, False, consumer, monitor)

    def get_merge_manager(self, results_obj, source_obj, original_obj, latest_obj):
        return None

    def get_read_only_object(self, item, version, ok_to_upgrade, consumer, monitor):
        if not isinstance(item, DatabaseItem):
            raise IOException("Unsupported content type: " + str(item.__class__.__name__))
        try:
            db_item = (DatabaseItem)(item)
            bf = db_item.open()
            dbh = DBHandle(bf)
            success = False
            try:
                manager = VTSessionDB.get_vt_session(dbh, OpenMode.READ_ONLY, consumer, monitor)
                success = True
                return manager
            finally:
                if not success:
                    dbh.close()
        except (IOException):
            raise
        except Exception as e:
            Msg.error(self, "getImmutableObject failed", e)
            msg = str(e).strip() or str(e.__class__.__name__)
            raise IOException("Open failed: " + msg)

    def is_private_content_type(self):
        return True

# Note that ResourceManager and DBHandle are not provided in the code snippet.
