Here is a translation of the Java code into equivalent Python:

```Python
import os
from urllib.parse import urlparse

class GHelpClassLoader:
    def __init__(self, module_directory=None):
        self.module_directory = module_directory

    def find_resource(self, name):
        url = super().find_resource(name)
        if url is not None:
            return url
        
        if self.module_directory is not None:
            url = self.find_in_module_directory(name)
            if url is not None:
                return url
        
        return self.find_in_jar_file(name)

    def find_in_jar_file(self, name):
        resource_url = f"help/{name}"
        try:
            return ResourceManager.get_resource(resource_url)
        except Exception as e:
            print(f"Unexpected exception: {e}")
            return None

    def find_in_module_directory(self, name):
        if self.module_directory is None:
            # must be the master loader
            return None
        
        help_file_path = os.path.join(self.module_directory, name)
        try:
            return urlparse(help_file_path).geturl()
        except Exception as e:
            print(f"Unexpected exception: {e}")
            return None

class ResourceManager:
    @staticmethod
    def get_resource(name):
        # implementation of resource manager here
        pass

# usage example
module_directory = "path/to/module"
loader = GHelpClassLoader(module_directory)
url = loader.find_resource("resource_name")
print(url)  # prints the URL for the given item, or None if not found
```

Please note that this is a translation of Java code into Python and it may require some adjustments to work correctly in your specific use case.