Here is a translation of the Java code into equivalent Python:

```Python
import os
import urllib.parse


class GhidraClassLoader:
    CP = "CLASSPATH"

    def __init__(self):
        self.parent = None

    def add_url(self, url: str) -> None:
        if not isinstance(url, str):
            raise TypeError("URL must be a string")

        try:
            parsed_url = urllib.parse.urlparse(url)
            path = os.path.join(parsed_url.netloc, parsed_url.path)

            # Add the URL to the classpath
            self._update_classpath(path)

        except ValueError as e:
            print(f"Invalid URL: {url}")

    def _update_classpath(self, new_path: str) -> None:
        if not isinstance(new_path, str):
            raise TypeError("Path must be a string")

        # Update the classpath
        current_classpath = os.environ.get(self.CP)
        if current_classpath is None:
            os.environ[self.CP] = new_path
        else:
            os.environ[self.CP] = f"{current_classpath}{os.pathsep}{new_path}"

    def add_path(self, path: str) -> bool:
        try:
            self.add_url(path)
            return True

        except ValueError as e:
            print(f"Invalid URL: {path}")
            return False
```

Please note that Python does not have a direct equivalent to Java's `URLClassLoader` or the concept of classpaths. This code is an attempt to translate the functionality into Python, but it may not be exactly equivalent due to these differences.

Also, this translation assumes that you want to add URLs as paths in your system environment variable CLASSPATH.