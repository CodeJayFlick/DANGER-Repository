import re
from ghidra.program.model.data import *

class DataTypeUrl:
    PROTOCOL = "datatype"
    URL_PATTERN = re.compile(PROTOCOL + r":/(\\d+)\\?uid=(\\d*)&name=(.+)")
    
    def __init__(self, dt):
        self.datatype_manager_id = dt.get_datatype_manager().get_universal_id()
        self.data_type_id = dt.get_universal_id()
        self.data_type_name = dt.name

    @classmethod
    def from_url(cls, url):
        match = cls.URL_PATTERN.match(url)
        if not match:
            raise ValueError(f"Invalid data type URL: {url}")
        
        dtm_id = int(match.group(1))
        dt_id = int(match.group(2)) if match.group(2) else None
        name = match.group(3)

        return cls(DataType(dtm_id, name))

    def get_datatype_manager_id(self):
        return self.datatype_manager_id

    def get_data_type_id(self):
        return self.data_type_id

    def get_data_type_name(self):
        return self.data_type_name

    def get_datatype(self, service):
        manager = self.find_manager(service)
        if not manager:
            return None
        
        if not self.data_type_id:
            # The ID will be null for built-in types.  In that case, the name will not be
            # null.  Further, built-ın types live at the root, so we can just ask for the
            # type by name.
            return manager.get_datatype(DataTypePath(CategoryPath.ROOT, self.data_type_name))
        else:
            dt = manager.find_datatype(self.data_type_id)
            return dt

    def find_manager(self, service):
        managers = [m for m in service.get_managers()]
        for mg in managers:
            if mg.get_universal_id() == self.datatype_manager_id:
                return mg
        return None


def main():
    # Example usage:
    url = "datatype:/12345678?uid=12345678&name=Bob"
    dt_url = DataTypeUrl.from_url(url)
    
    service = ...  # Your service instance here
    
    datatype = dt_url.get_datatype(service)

if __name__ == "__main__":
    main()
