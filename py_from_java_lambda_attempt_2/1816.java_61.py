Here is a translation of the provided Java code into equivalent Python:

```Python
class SBPlatformConnectOptions:
    def __init__(self):
        pass

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        if not isinstance(value, str):
            raise TypeError("URL must be a string")
        self._set_url(value)

    @property
    def rsync_enabled(self):
        return self._rsync_enabled

    @rsync_enabled.setter
    def rsync_enabled(self, value):
        if not isinstance(value, bool):
            raise TypeError("Rsync enabled must be a boolean")
        self._enable_rsync(str(value))

    @property
    def local_cache_directory(self):
        return self._local_cache_directory

    @local_cache_directory.setter
    def local_cache_directory(self, value):
        if not isinstance(value, str):
            raise TypeError("Local cache directory must be a string")
        self._set_local_cache_directory(value)

    def _set_url(self, url):
        # This method should call the equivalent C++ function to set URL.
        pass

    def _enable_rsync(self, options, remote_path_prefix, omit_remote_hostname):
        # This method should call the equivalent C++ function to enable Rsync.
        pass

    def _disable_rsync(self):
        # This method should call the equivalent C++ function to disable Rsync.
        pass

    def _set_local_cache_directory(self, path):
        # This method should call the equivalent C++ function to set local cache directory.
        pass
```

Please note that this is a Python translation of your Java code. The actual implementation depends on how you are using these classes in your program and what functionality they provide.