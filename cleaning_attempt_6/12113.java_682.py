import threading

class AddressSetPropertyMapDB:
    MY_PREFIX = "AddressSet - "
    TABLE_PREFIX = f"{AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX}{MY_PREFIX}"

    def __init__(self, program: 'ProgramDB', map_name: str, err_handler=None, addr_map='AddressMap', lock=threading.Lock()):
        self.program = program
        self.map_name = map_name
        self.lock = lock

        self.property_map = AddressRangeMapDB(program.get_db_handle(), addr_map, lock, f"{MY_PREFIX}{map_name}", err_handler)

    @staticmethod
    def get_property_map(program: 'ProgramDB', map_name: str, err_handler=None, addr_map='AddressMap', lock=threading.Lock()):
        with lock:
            dbh = program.get_db_handle()
            if dbh.get_table(TABLE_PREFIX + map_name) is not None:
                return AddressSetPropertyMapDB(program, map_name)
            else:
                return None

    @staticmethod
    def create_property_map(program: 'ProgramDB', map_name: str, err_handler=None, addr_map='AddressMap', lock=threading.Lock()):
        with lock:
            dbh = program.get_db_handle()
            if dbh.get_table(TABLE_PREFIX + map_name) is not None:
                raise DuplicateNameException(f"Address Set Property Map named {map_name} already exists.")
            else:
                return AddressSetPropertyMapDB(program, map_name)

    def add(self, start_addr: 'Address', end_addr: 'Address'):
        self.check_deleted()
        with self.lock:
            try:
                self.property_map.paint_range(start_addr, end_addr)
                self.program.set_changed(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, None, self.map_name)
            finally:
                self.lock.release()

    def add(self, address_set: 'AddressSetView'):
        self.check_deleted()
        with self.lock:
            try:
                for range in address_set.get_address_ranges():
                    start_addr = range.min_address
                    end_addr = range.max_address
                    self.add(start_addr, end_addr)
                self.program.set_changed(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, None, self.map_name)
            finally:
                self.lock.release()

    def set(self, address_set: 'AddressSetView'):
        self.check_deleted()
        with self.lock:
            try:
                self.clear()
                self.add(address_set)
                self.program.set_changed(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, None, self.map_name)
            finally:
                self.lock.release()

    def remove(self, start_addr: 'Address', end_addr: 'Address'):
        self.check_deleted()
        with self.lock:
            try:
                self.property_map.clear_range(start_addr, end_addr)
                self.program.set_changed(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, None, self.map_name)
            finally:
                self.lock.release()

    def remove(self, address_set: 'AddressSetView'):
        self.check_deleted()
        with self.lock:
            try:
                for range in address_set.get_address_ranges():
                    start_addr = range.min_address
                    end_addr = range.max_address
                    self.remove(start_addr, end_addr)
                self.program.set_changed(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, None, self.map_name)
            finally:
                self.lock.release()

    def get_address_set(self):
        self.check_deleted()
        with self.lock:
            try:
                return self.property_map.get_address_set()
            finally:
                self.lock.release()

    def get_addresses(self):
        self.check_deleted()
        with self.lock:
            try:
                if not self.property_map.is_empty():
                    set = self.get_address_set()
                    return set.get_addresses(True)
                else:
                    return EmptyAddressIterator()
            finally:
                self.lock.release()

    def get_address_ranges(self):
        self.check_deleted()
        with self.lock:
            try:
                return self.property_map.get_address_ranges()
            finally:
                self.lock.release()

    def clear(self):
        self.check_deleted()
        with self.lock:
            try:
                self.property_map.dispose()
                self.program.set_changed(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, None, self.map_name)
            finally:
                self.lock.release()

    def contains(self, addr: 'Address'):
        self.check_deleted()
        with self.lock:
            try:
                return self.property_map.get_value(addr) is not None
            finally:
                self.lock.release()

    def delete(self):
        self.property_map.dispose()
        self.invalid = True

    def move_address_range(self, from_addr: 'Address', to_addr: 'Address', length: int, monitor=None):
        with self.lock:
            try:
                range_end = from_addr.add_no_wrap(length - 1)

                current_set = AddressSet()
                for range in self.property_map.get_address_ranges(from_addr, range_end):
                    if monitor is not None and monitor.check_canceled():
                        raise CancelledException
                    current_set.add(range)
                self.property_map.clear_range(from_addr, range_end)

                for addr in current_set.get_addresses(True):
                    offset = addr.subtract(from_addr)
                    start_addr = to_addr.add(offset)
                    end_addr = to_addr.add_no_wrap(length - 1).subtract(from_addr) + from_addr
                    self.property_map.paint_range(start_addr, end_addr)
            finally:
                self.lock.release()

    def check_deleted(self):
        if self.invalid:
            raise ConcurrentModificationException("AddressSetPropertyMap has been deleted.")
