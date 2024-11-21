Here is the equivalent Python code:

```Python
class MacJavaFinder:
    def __init__(self):
        pass

    def get_java_root_install_dirs(self):
        java_root_install_dirs = []
        java_root_install_dirs.append('/Library/Java/JavaVirtualMachines')
        return java_root_install_dirs

    def get_java_home_sub_dir_path(self):
        return 'Contents/Home'
```

Note that Python does not have direct equivalents to Java's `package`, `import` statements, or the concept of classes extending other classes. The equivalent code in Python is a class definition with methods for each method defined in the original Java code.