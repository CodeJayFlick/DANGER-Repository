Here is the equivalent Python code:

```Python
import os

class FileSystemInitializer:
    def run(self):
        for file in os.listdir('/tmp'):
            if file.startswith('ghidra_') and file.endswith('.db'):
                try:
                    os.remove(os.path.join('/tmp', file))
                except Exception as e:
                    print(f"Error removing {file}: {str(e)}")

    @property
    def name(self):
        return "FileSystem Module"

# Usage example
initializer = FileSystemInitializer()
initializer.run()

print(initializer.name)
```

Please note that this Python code does not exactly replicate the Java code. The main differences are:

1. In Java, `PackedDatabase` is a class with static methods, whereas in Python, we use built-in functions like `os.listdir`, `os.path.join`, and `os.remove`.

2. The `cleanupOldTempDatabases()` method in Java does not have an equivalent direct translation to Python because it seems to be responsible for cleaning up old temporary databases. In the provided code snippet, I've replaced this with a simple example of removing files from `/tmp` that start with 'ghidra_' and end with '.db'. This is just a rough approximation.

3. The `getName()` method in Java has been translated into a Python property named `name`.