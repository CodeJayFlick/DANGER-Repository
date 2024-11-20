class EmptyVTSession:
    def create_match_set(self, correlator):
        return None

    def get_association_manager(self):
        return None

    def get_destination_program(self):
        return None

    def get_match_sets(self):
        return []

    def get_name(self):
        return "Empty"

    def get_source_program(self):
        return None

    def save(self, *args, **kwargs):
        pass  # do nothing

    def db_error(self, e):
        pass  # do nothing

    def add_listener(self, dol):
        pass  # do nothing

    def remove_listener(self, dol):
        pass  # do nothing

    def add_close_listener(self, listener):
        pass  # do nothing

    def remove_close_listener(self, listener):
        pass  # do nothing

    def create_private_event_queue(self, listener, max_delay):
        return None

    def remove_private_event_queue(self, id):
        return False

    def flush_private_event_queue(self, id):
        pass  # do nothing

    def create_match_tag(self, name):
        return None

    def delete_match_tag(self, tag):
        pass  # do nothing

    def get_match_tags(self):
        return set()

    def get_manual_match_set(self):
        raise AssertionError("EmptyVTSession has no manual match set!")

    def get_implied_match_set(self):
        raise AssertionError("EmptyVTSession has no implied match set!")

    def get_matches(self, association):
        return []

    def add_association_hook(self, hook):
        pass  # do nothing

    def remove_association_hook(self, hook):
        pass  # do nothing

    def add_synchronized_domain_object(self, domain_obj):
        pass  # do nothing

    def end_transaction(self, transaction_id, commit):
        pass  # do nothing

    def get_current_transaction(self):
        return None

    def get_synchronized_domain_objects(self):
        return []

    def has_terminated_transaction(self):
        return False

    def release_synchronized_domain_object(self):
        pass  # do nothing

    def start_transaction(self, description):
        return 0

    def start_transaction(self, description, listener):
        return 0

    def add_consumer(self, consumer):
        return False

    def can_lock(self):
        return False

    def can_save(self):
        return False

    def flush_events(self):
        pass  # do nothing

    def force_lock(self, rollback, reason):
        pass  # do nothing

    def get_consumer_list(self):
        return []

    def is_used_by(self, consumer):
        return False

    def get_description(self):
        return None

    def get_domain_file(self):
        return None

    def get_metadata(self):
        return {}

    def get_modification_number(self):
        return 0

    def get_options(self, property_list_name):
        return []

    def get_options_names(self):
        return []

    def has_exclusive_access(self):
        return False

    def is_changeable(self):
        return False

    def is_changed(self):
        return False

    def is_closed(self):
        return False

    def is_locked(self):
        return False

    def is_temporary(self):
        return False

    def lock(self, reason):
        return False

    def release(self, consumer):
        pass  # do nothing

    def save_to_packed_file(self, file, monitor):
        pass  # do nothing

    def set_events_enabled(self, v):
        pass  # do nothing

    def is_sending_events(self):
        return True

    def set_name(self, name):
        pass  # do nothing

    def set_temporary(self, state):
        pass  # do nothing

    def unlock(self):
        pass  # do nothing

    def add_transaction_listener(self, listener):
        pass  # do nothing

    def can_redo(self):
        return False

    def can_undo(self):
        return False

    def clear_undo(self):
        pass  # do nothing

    def get_redo_name(self):
        return None

    def get_undo_name(self):
        return None

    def redo(self, *args, **kwargs):
        pass  # do nothing

    def remove_transaction_listener(self, listener):
        pass  # do nothing

    def undo(self, *args, **kwargs):
        pass  # do nothing

    def update_destination_program(self, new_program):
        pass  # do nothing

    def update_source_program(self, new_program):
        pass  # do nothing
