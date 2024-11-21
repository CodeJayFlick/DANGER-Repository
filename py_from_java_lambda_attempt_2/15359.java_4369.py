Here is the translation of the Java code to Python:
```python
import random

class PermissionsUtil:
    TAG = f"{__class__.__name__}"

    class OnPermissionListener:
        def on_permission_granted(self, permissions):
            pass

        def on_permission_denied(self, permissions):
            pass

        def on_should_show_request_permission_rationale(self, permissions):
            pass

    @staticmethod
    def check_permissions(context: object, on_permission_listener: 'OnPermissionListener' = None, *permissions) -> None:
        if build_version.sdk_int < 16 or not permissions:
            if on_permission_listener is not None:
                on_permission_listener.on_permission_granted(permissions)
            return

        request_code = random.randint(0, 1024)
        permission_listeners[request_code] = on_permission_listener

        context.startActivity(Intent(context, PermissionActivity) \
                                 .addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION) \
                                 .putExtra('PERMISSIONS', permissions) \
                                 .putExtra('REQUEST_CODE', request_code))

    _permission_listeners: dict[int, 'OnPermissionListener'] = {}
    _random: random.Random = random.Random()

    @staticmethod
    def get_permission_listener(request_code: int) -> 'OnPermissionListener':
        listener = permission_listeners.get(request_code)
        if listener is not None:
            del permission_listeners[request_code]
        return listener

permission_listeners: dict[int, PermissionsUtil.OnPermissionListener] = {}
```
Note that I've used the `f` string notation to create a formatted string for the `TAG` attribute. In Python, we don't have an equivalent concept of "final" classes or methods like in Java, so I removed those annotations.

Also, I replaced the Android-specific imports (e.g., `android.content.Context`) with generic Python types (`object`, `dict`, etc.). The code assumes that you will provide a suitable implementation for the `PermissionActivity` class and other dependencies.