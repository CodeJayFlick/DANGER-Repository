class DbgModuleMemory:
    def get_name(self):
        pass  # Implement this method in your subclass

    def get_id(self):
        pass  # Implement this method in your subclass

    def get_vma_start(self):
        pass  # Implement this method in your subclass

    def get_vma_end(self):
        pass  # Implement this method in your subclass

    def get_type(self):
        pass  # Implement this method in your subclass

    def get_protect(self):
        return []  # Return an empty list, implement the actual logic in your subclass

    def get_allocation_protect(self):
        return []  # Return an empty list, implement the actual logic in your subclass

    def get_allocation_base(self):
        pass  # Implement this method in your subclass

    def get_state(self):
        pass  # Implement this method in your subclass

    def is_read(self):
        pass  # Implement this method in your subclass

    def is_write(self):
        pass  # Implement this method in your subclass

    def is_exec(self):
        pass  # Implement this method in your subclass
