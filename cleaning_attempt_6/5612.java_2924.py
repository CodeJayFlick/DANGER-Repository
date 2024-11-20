class OpenCloseManager:
    def __init__(self):
        self.map = {}
        self.listeners = []

    def open_data(self, data):
        if not data.get_component(0):
            return False
        
        addr = data.get_min_address()
        path = data.get_component_path()

        if self.is_open(addr, path):
            return False

        self.open(addr, path)
        self.notify_data_toggled()
        return True

    def close_data(self, data):
        if not data.get_component(0):
            return
        
        addr = data.get_min_address()
        path = data.get_component_path()

        if not self.is_open(addr, path):
            return
        
        self.close(addr, path)
        self.notify_data_toggled()

    def open(self, address, path):
        levels = self.map.get(address)

        if (levels is None) or (len(levels) < len(path)):
            exact_open(address, path)
            return

        for i in range(len(path)):
            if levels[i + 1] != path[i]:
                if levels[i + 1] == -1:
                    exact_open(address, path)
                    return
                levels[i + 1] = path[i]

    def exact_open(self, address, path):
        new_levels = [0]
        System.arraycopy(path, 0, new_levels, 1, len(path))
        self.map[address] = new_levels

    def close(self, address, path):
        if not self.is_open(address, path):
            return
        
        levels = self.map.get(address)

        for i in range(len(path)):
            if levels[i + 1] == -1:
                continue
            elif levels[i + 1] != path[i]:
                return

        levels[len(path)] = -1
        actual_length = compute_actual_length(levels)
        
        if actual_length == 0:
            self.map.pop(address, None)
            return
        
        new_levels = levels[:actual_length]
        self.map[address] = new_levels

    def is_open(self, address):
        return self.is_open(address, [])

    def is_open(self, address, path):
        levels = self.map.get(address)

        if (levels is None) or (len(levels) == 0):
            return False
        
        for i in range(len(path)):
            if levels[i + 1] != -1 and levels[i + 1] != path[i]:
                return False

    def get_open_index(self, address, path):
        levels = self.map.get(address)

        if (levels is None) or (len(levels) == 0):
            return -1
        
        for i in range(len(path)):
            if len(levels) < i + 2:
                return -1
            elif levels[i + 1] != -1 and levels[i + 1] != path[i]:
                return levels[i + 1]

    def open_all_data(self, program, addresses):
        self.toggle_all_data_in_addresses(True, program, addresses)

    def toggle_all_data_in_addresses(self, open_state, program, addresses):
        monitor = TaskMonitor()
        start_addr = addresses.get_min_address()

        listing = program.get_listing()
        iterator = listing.get_data(addresses, True)
        
        while iterator.has_next():
            if monitor.is_cancelled:
                return
            
            data = iterator.next()
            
            self.toggle_data_recursively(data, open_state, monitor)

    def toggle_open(self, data):
        self.toggle_top_level_data(data)
        self.notify_data_toggled()

    def notify_data_toggled(self):
        for l in self.listeners:
            l.state_changed(None)

    def add_change_listener(self, listener):
        self.listeners.append(listener)

    def remove_change_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)
