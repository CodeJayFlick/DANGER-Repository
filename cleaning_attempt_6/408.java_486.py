class DebugModuleInfo:
    def __init__(self, image_file_handle: int, base_offset: int, module_size: int, 
                 module_name: str, image_name: str, check_sum: int, time_date_stamp: int):
        self.image_file_handle = image_file_handle
        self.base_offset = base_offset
        self.module_size = module_size
        self.module_name = module_name
        self.image_name = image_name
        self.check_sum = check_sum
        self.time_date_stamp = time_date_stamp

    def __str__(self):
        return hex(self.base_offset)

    @property
    def module_name(self) -> str:
        return self._module_name

    @module_name.setter
    def module_name(self, value: str):
        self._module_name = value

    @property
    def image_name(self) -> str:
        return self._image_name

    @image_name.setter
    def image_name(self, value: str):
        self._image_name = value


# Example usage:

debug_module_info = DebugModuleInfo(1, 2, 3, "module name", "image name", 4, 5)
print(debug_module_info)  # prints the base offset in hexadecimal
