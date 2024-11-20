Here is the translation of the given Java code into equivalent Python:

```Python
class ISO9660FileSystem:
    def __init__(self, fsrl: 'FSRLRoot', fs_service: 'FileSystemService'):
        super().__init__(fsrl, fs_service)

# You can use this class like this:
iso9660_file_system = ISO9660FileSystem(None, None)
```

Please note that Python does not have direct equivalent of Java's `@FileSystemInfo` annotation. In Python, you would typically add docstrings to your classes and methods for documentation purposes.

Also, the type hints in the constructor are used by some IDEs or linters to provide better code completion and error detection. They do not affect how the class is actually used at runtime.