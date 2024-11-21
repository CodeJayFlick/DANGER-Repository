import ctypes
from comtypes import BSTR, BOOL

class DataModelScriptImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # No direct equivalent in Python
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_name(self):
        bref = BSTR()
        result = self.jna_data.get_name(bref)
        if not isinstance(result, str):  # Assuming getName returns a string
            raise ValueError("Invalid name")
        return result

    def rename(self, script_name: str) -> None:
        self.jna_data.rename(script_name)

    def populate(self, content_stream):
        self.jna_data.populate(content_stream)

    def execute(self, client):
        p_client = client.get_pointer()
        self.jna_data.execute(p_client)

    def unlink(self):
        self.jna_data.unlink()

    def is_invocable(self) -> bool:
        b_is_invocable = BOOL()
        result = self.jna_data.is_invocable(b_is_invocable)
        return b_is_invocable.value

    def invoke_main(self, client):
        p_client = client.get_pointer()
        self.jna_data.invoke_main(p_client)

# Usage example:
jna_data = IDataModelScript()  # Assuming this is the equivalent of IDataModelScript
script_impl = DataModelScriptImpl(jna_data)
print(script_impl.get_name())
