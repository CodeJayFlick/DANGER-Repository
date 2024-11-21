class Platform:
    def __init__(self):
        self.version = None
        self.os_prefix = None
        self.os_arch = None
        self.flavor = None
        self.cuda_arch = None
        self.libraries = []
        self.placeholder = False

    @classmethod
    def from_url(cls, url):
        platform = cls.from_system()
        try:
            with url.open() as conf:
                prop = Properties()
                prop.load(conf)
                if not "version" in prop:
                    raise ValueError("Version key is required in <engine>.properties file.")
                platform.version = prop["version"]
                platform.placeholder = "placeholder" in prop
                flavor_prefixed_classifier = prop.get("classifier", "")
                library_list = prop.get("libraries", "")
                if not library_list:
                    platform.libraries = []
                else:
                    platform.libraries = [x.strip() for x in library_list.split(",")]
                if flavor_prefixed_classifier:
                    tokens = flavor_prefixed_classifier.split("-")
                    platform.flavor = tokens[0]
                    platform.os_prefix = tokens[1]
                    platform.os_arch = tokens[2]
        except Exception as e:
            raise
        return platform

    @classmethod
    def from_system(cls, version=None):
        platform = cls.from_system()
        if version is not None:
            platform.version = version
        return platform

    @classmethod
    def from_system(cls):
        platform = Platform()
        os_name = sys.platform
        if os_name.startswith("win"):
            platform.os_prefix = "win"
        elif os_name.startswith("darwin"):
            platform.os_prefix = "osx"
        elif os_name.startswith("linux") or os_name == "linux2":
            platform.os_prefix = "linux"
        else:
            raise AssertionError(f"Unsupported platform: {os_name}")
        platform.os_arch = sys.platform
        if platform.os_arch.lower() == "darwin":
            platform.os_arch = "x86_64"
        elif platform.os_arch.lower().startswith("win"):
            platform.os_arch = "amd64"
        if CudaUtils.get_gpu_count() > 0:
            platform.flavor = f"cu{CudaUtils.get_cuda_version_string()}".lower()
            platform.cuda_arch = CudaUtils.get_compute_capability(0)
        else:
            platform.flavor = "cpu"
        return platform

    def get_version(self):
        return self.version

    def get_os_prefix(self):
        return self.os_prefix

    def get_os_arch(self):
        return self.os_arch

    def get_flavor(self):
        return self.flavor

    def get_classifier(self):
        if not self.placeholder:
            return f"{self.os_prefix}-{self.os_arch}"
        else:
            return "cpu"

    def get_cuda_arch(self):
        return self.cuda_arch

    def get_libraries(self):
        return self.libraries

    def is_placeholder(self):
        return self.placeholder

    @classmethod
    def matches(cls, system, strict_model=False):
        if not cls.from_system().os_prefix == system.os_prefix or \
           not cls.from_system().os_arch == system.os_arch:
            return False
        if "cu" in system.flavor and "cpu" != cls.get_flavor():
            return False
        return True

# usage example
platform = Platform.from_url(url)
print(platform.get_version())
