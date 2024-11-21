class VersionInfoTransferable:
    local_version_info_flavor = create_local_version_info_flavor()

    def __init__(self, domain_file_path: str, version: int):
        self.version_info = VersionInfo(domain_file_path, version)

    @staticmethod
    def create_local_version_info_flavor():
        try:
            return DataFlavor("application/octet-stream", "Local DomainFile Version object")
        except Exception as e:
            print(f"Error creating local version info flavor: {e}")

    flavors = [local_version_info_flavor]

    def get_transfer_data_flavors(self):
        return self.flavors

    def is_data_flavor_supported(self, flavor):
        return flavor in self.flavors

    def get_transfer_data(self, flavor):
        if isinstance(flavor, str) and flavor == "application/octet-stream":
            return self.version_info
        raise UnsupportedFlavorException("Unsupported flavor")

class DataFlavor:
    pass

class VersionInfo:
    def __init__(self, domain_file_path: str, version: int):
        self.domain_file_path = domain_file_path
        self.version = version


if __name__ == "__main__":
    transferable = VersionInfoTransferable("path", 1)
