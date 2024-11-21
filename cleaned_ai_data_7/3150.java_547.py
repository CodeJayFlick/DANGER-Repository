class CreateDataBackgroundCmd:
    EVENT_LIMIT = 1000

    def __init__(self, addr_set: 'AddressSetView', data_type: 'DataType', stack_pointers=False):
        self.addr_set = addr_set
        self.new_data_type = data_type.clone()
        self.bytes_applied = 0
        self.num_data_created = 0
        self.stack_pointers = stack_pointers

    def apply_to(self, obj: 'DomainObject', monitor: 'TaskMonitor') -> bool:
        return self.do_apply_to(obj, monitor)

    def do_apply_to(self, obj: 'DomainObject', monitor: 'TaskMonitor') -> bool:
        program = Program(obj)
        listing = program.get_listing()
        iter = listing.get_instructions(addr_set, True)
        if iter.has_next():
            print("Can't create data because the current selection contains instructions")
            return False

        addr = addr_set.get_min_address()
        data = listing.get_data_at(addr)
        if data is None:
            print(f"Can not create Data at address {addr}")
            return False

        existing_dt = data.get_data_type()

        new_data_type = self.reconcile_applied_data(existing_dt, self.new_data_type, self.stack_pointers)

        monitor.initialize(self.addr_set.num_addresses())
        it = addr_set.get_address_ranges()
        while it.has_next() and not monitor.is_cancelled():
            range_ = it.next()
            try:
                self.create_data(range_.get_min_address(), range_.get_max_address(), new_data_type, program, monitor)
            except Exception as e:
                print(e.message)
                if self.num_data_created == 0:
                    return False

        if self.num_data_created == 0:
            print("Not Enough space to create Data")
            return False
        return True

    def reconcile_applied_data(self, existing_dt: 'DataType', new_dt: 'DataType', stack_pointers=False) -> 'DataType':
        # This method is not implemented in the original Java code.
        pass

    def create_data(self, start: Address, end: Address, data_type: 'DataType', program: Program, monitor: TaskMonitor):
        listing = program.get_listing()
        listing.clear_code_units(start, end, False)
        length = (end - start) + 1
        while start <= end:
            if monitor.is_cancelled():
                return

            d = listing.create_data(start, data_type, length)
            data_len = d.length
            start += data_len
            length -= data_len
            self.bytes_applied += data_len

            monitor.set_progress(self.bytes_applied)
            if (self.num_data_created + 1) % 10000 == 0:
                monitor.message(f"Created {self.num_data_created}")
