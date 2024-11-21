class GhidraBundle:
    def __init__(self, bundle_host: 'BundleHost', file: 'ResourceFile', enabled: bool = False, system_bundle: bool = False):
        self.bundle_host = bundle_host
        self.file = file
        self.enabled = enabled
        self.system_bundle = system_bundle

    def clean(self) -> bool:
        # This method should be implemented in the subclass.
        pass

    def build(self, writer: 'PrintWriter') -> bool:
        try:
            return self.clean()
        except Exception as e:
            print(f"Error during build: {e}")
            return False

    def get_location_identifier(self) -> str:
        # This method should be implemented in the subclass.
        pass

    def get_all_requirements(self) -> list['BundleRequirement']:
        try:
            # This method should be implemented in the subclass.
            pass
        except Exception as e:
            print(f"Error getting requirements: {e}")
            return []

    def get_all_capabilities(self) -> list['BundleCapability']:
        try:
            # This method should be implemented in the subclass.
            pass
        except Exception as e:
            print(f"Error getting capabilities: {e}")
            return []

    @property
    def file_(self):
        return self.file

    @file_.setter
    def set_file(self, value):
        self.file = value

    @property
    def enabled_(self):
        return self.enabled

    @enabled_.setter
    def set_enabled(self, value):
        self.enabled = value

    @property
    def system_bundle_(self):
        return self.system_bundle

    @system_bundle_.setter
    def set_system_bundle(self, value):
        self.system_bundle = value

    @staticmethod
    def get_type(file: 'ResourceFile') -> 'Type':
        if file.is_directory():
            return GhidraBundle.Type.SOURCE_DIR
        filename = file.name.lower()
        if filename.endswith('.bnd'):
            return GhidraBundle.Type.BND_SCRIPT
        elif filename.endswith('.jar'):
            return GhidraBundle.Type.JAR
        else:
            return GhidraBundle.Type.INVALID

    @staticmethod
    def get_osgi_bundle(self) -> 'Bundle':
        bundle = self.bundle_host.get osgi_bundle(self.location_identifier)
        if bundle is None or bundle.state != Bundle.ACTIVE:
            return None
        return bundle

    @property
    def active_(self):
        bundle = self.get_osgi_bundle()
        return bundle is not None and bundle.state == Bundle.ACTIVE

    class Type(enum.Enum):
        BND_SCRIPT = 1
        JAR = 2
        SOURCE_DIR = 3
        INVALID = 4


class ResourceFile:
    def __init__(self, path: str):
        self.path = path

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    def is_directory(self) -> bool:
        # This method should be implemented in the subclass.
        pass


class BundleHost:
    def get_osgi_bundle(self, location_identifier: str) -> 'Bundle':
        # This method should be implemented in the subclass.
        pass
