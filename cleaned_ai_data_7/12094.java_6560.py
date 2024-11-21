class NamespaceManager:
    NAMESPACE_MAP_NAME = "SCOPE ADDRESSES"

    def __init__(self, handle, err_handler, addr_map, open_mode, lock):
        self.err_handler = err_handler
        self.addr_map = addr_map
        self.lock = lock

        if handle.get_table("Scope") is not None:
            raise VersionException("Program is transient development format, not supported")

        self.namespace_map = AddressRangeMapDB(handle, addr_map, lock, NAMESPACE_MAP_NAME,
                                                 err_handler, LongField.INSTANCE, True)

    def delete_address_range(self, start_addr, end_addr):
        with self.lock:
            try:
                self.namespace_map.clear_range(start_addr, end_addr)
            finally:
                clear_cache()
                self.lock.release()

    def invalidate_cache(self, all=False):
        clear_cache()

    def set_program(self, program_db):
        self.symbol_mgr = program_db.get_symbol_table()
        self.global_namespace = program_db.get_global_namespace()

    def program_ready(self, open_mode, current_revision):
        # Nothing to do
        pass

    def db_error(self, e):
        self.err_handler.db_error(e)

    @property
    def global_namespace(self):
        return self._global_namespace

    @global_namespace.setter
    def global_namespace(self, value):
        self._global_namespace = value

    def set_body(self, namespace, address_set_view):
        if address_set_view.get_num_addresses() > 0x7fffffff:
            raise ValueError("Namespace body size must be less than 0x7fffffff byte addresses")

        with self.lock:
            try:
                old_body = remove_body(namespace)
                range_ = overlaps_namespace(address_set_view)
                if range_ is not None:
                    do_set_body(namespace, old_body)
                    raise OverlappingNamespaceException(range_.get_min_address(), range_.get_max_address())
                else:
                    do_set_body(namespace, address_set_view)
            finally:
                clear_cache()
                self.lock.release()

    def remove_body(self, namespace):
        with self.lock:
            try:
                address_set = get_address_set(namespace)
                for address_range in address_set.get_address_ranges():
                    self.namespace_map.clear_range(address_range.get_min_address(), address_range.get_max_address())
                return address_set
            finally:
                clear_cache()
                self.lock.release()

    def overlaps_namespace(self, address_set_view):
        range_iter = address_set_view.get_address_ranges()
        for address_range in range_iter:
            existing_range = namespace_map.get_address_ranges(address_range.get_min_address(), address_range.get_max_address())
            if existing_range is not None and next(existing_range) is not None:
                return existing_range.next()

    def get_namespaces_overlapping(self, address_set_view):
        id_set = set()
        range_iter = address_set_view.get_address_ranges()
        for address_range in range_iter:
            namespace_ranges = self.namespace_map.get_address_ranges(address_range.get_min_address(), address_range.get_max_address())
            while True:
                try:
                    existing_range = next(namespace_ranges)
                    field = self.namespace_map.get_value(existing_range.get_min_address())
                    id_ = field.get_long_value()
                    if not id_set.add(id_):
                        break
                except StopIteration:
                    break

        list_ = [Namespace(s) for s in symbol_mgr.get_symbols() if isinstance(s, Namespace)]
        return iter(list_)

    def get_address_set(self, namespace_id):
        with self.lock:
            try:
                return self.namespace_map.get_address_set(LongField(namespace_id))
            finally:
                clear_cache()
                self.lock.release()

    @property
    def last_body_namespace(self):
        return self._last_body_namespace

    @last_body_namespace.setter
    def last_body_namespace(self, value):
        self._last_body_namespace = value

    @property
    def last_body(self):
        return self._last_body

    @last_body.setter
    def last_body(self, value):
        self._last_body = value

class AddressRangeMapDB:
    pass

class LongField:
    INSTANCE = None

def clear_cache():
    # Nothing to do here.
    pass

class OverlappingNamespaceException(Exception):
    pass

class VersionException(Exception):
    pass
