class DBTraceProgramViewPropertyMapManager:
    def __init__(self, program):
        self.program = program

    def create_int_property_map(self, property_name) -> dict:
        # TODO Auto-generated method stub
        return {}

    def create_long_property_map(self, property_name) -> dict:
        # TODO Auto-generated method stub
        return {}

    def create_string_property_map(self, property_name) -> str:
        # TODO Auto-generated method stub
        return ""

    def create_object_property_map(self, property_name: str, object_class: type) -> any:
        # TODO Auto-generated method stub
        return None

    def create_void_property_map(self, property_name) -> dict:
        # TODO Auto-generated method stub
        return {}

    def get_property_map(self, property_name):
        # TODO Auto-generated method stub
        return {}

    def get_int_property_map(self, property_name) -> dict:
        # TODO Auto-generated method stub
        return {}

    def get_long_property_map(self, property_name) -> dict:
        # TODO Auto-generated method stub
        return {}

    def get_string_property_map(self, property_name) -> str:
        # TODO Auto-generated method stub
        return ""

    def get_object_property_map(self, property_name: str) -> any:
        # TODO Auto-generated method stub
        return None

    def get_void_property_map(self, property_name) -> dict:
        # TODO Auto-generated method stub
        return {}

    def remove_property_map(self, property_name):
        # TODO Auto-generated method stub
        return False

    def property_managers(self) -> Iterator[str]:
        # TODO Auto-Generated Method Stub
        return iter([])

    def remove_all(self, addr: int):
        # TODO Auto-generated method stub

    def remove_all(self, start_addr: int, end_addr: int, monitor=None):
        if monitor is not None:
            try:
                # TODO Auto-generated method stub
                pass
            except CancelledException as e:
                print(f"Cancelled Exception: {e}")
