Here's a translation of your Java interface into equivalent Python classes:

```Python
class SymbolStore:
    def __init__(self):
        self.admin_dir = None  # Initialize admin directory as None for now.

    def get_admin_dir(self) -> str:
        return self.admin_dir if self.admin_dir else "No Admin Directory Set"

    def get_file(self, path: str) -> str:
        return f"{path}"


class SymbolFileInfo:
    pass


def give_file(symbol_store: SymbolStore, symbol_file_info: SymbolFileInfo, file_path: str, filename: str):
    # For now, just print the given information.
    print(f"Given File Path: {file_path}, Filename: {filename}")
    return f"{symbol_store.get_admin_dir()}/{filename}"


def put_stream(symbol_store: SymbolStore, symbol_file_info: SymbolFileInfo, stream_data: bytes, filename: str):
    # For now, just write the data to a file.
    with open(f"{symbol_store.get_admin_dir()}/{filename}", "wb") as f:
        f.write(stream_data)
    return f"{symbol_store.get_admin_dir()}/{filename}"


def is_compressed_filename(filename: str) -> bool:
    if filename.endswith("_"):
        return True
    else:
        return False

```

Please note that Python does not support interfaces like Java. Instead, we use abstract classes or pure virtual methods to achieve similar functionality.