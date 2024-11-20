import os
from typing import List, Optional

class PermissionActivity:
    TAG = "PermissionActivity"

    def __init__(self):
        self._permissions_granted: List[str] = []
        self._permissions_denied: List[str] = []
        self._permission_listener: Optional[PermissionsUtil.OnPermissionListener] = None
        self._request_code: int = -1

    def on_create(self, savedInstanceState: dict) -> None:
        super().on_create(savedInstanceState)

        intent = getIntent()
        permissions = intent.getStringArrayExtra("PERMISSIONS")
        if not permissions or len(permissions) == 0:
            finish()

        request_code = intent.getIntExtra("REQUEST_CODE", -1)
        if request_code == -1:
            finish()

        self._permission_listener = PermissionsUtil.get_permission_listener(request_code)

        for permission in permissions:
            if not permission or not permission.strip():
                raise RuntimeError("Permission can't be null or empty")

            if ContextCompat.checkSelfPermission(self, permission) == PackageManager.PERMISSION_GRANTED:
                self._permissions_granted.append(permission)
            else:
                self._permissions_denied.append(permission)

        if len(self._permissions_denied) == 0:
            if not self._permissions_granted:
                raise RuntimeError("There are no permissions")
            elif self._permission_listener is not None:
                self._permission_listener.on_permission_granted(tuple(self._permissions_granted))
            finish()
        else:
            ActivityCompat.request_permissions(self, tuple(self._permissions_denied), request_code)

    def on_requestPermissionsResult(self, requestCode: int, permissions: List[str], grantResults: List[int]) -> None:
        if requestCode != self._request_code:
            finish()

        self._permissions_denied.clear()
        for i in range(len(permissions) - 1, -1, -1):
            if grantResults[i] == PackageManager.PERMISSION_GRANTED:
                self._permissions_granted.append(permissions[i])
            else:
                self._permissions_denied.append(permissions[i])

        if len(self._permissions_denied) == 0:
            if not self._permissions_granted:
                raise RuntimeError("There are no permissions")
            elif self._permission_listener is not None:
                self._permission_listener.on_permission_granted(tuple(self._permissions_granted))
            finish()
        else:
            should_request_permissions = [p for p in self._permissions_denied
                                           if ActivityCompat.should_show_request_permission_rationale(self, p)]
            if self._permission_listener is not None:
                self._permission_listener.on_permission_denied(tuple(self._permissions_denied))
                self._permission_listener.on_should_show_request_permission_rationale(tuple(should_request_permissions))
            finish()

    def on_pause(self) -> None:
        super().on_pause()
        if is_finishing():
            override_pending_transition(0, 0)

def getIntent() -> dict: ...
def finish() -> None: ...
def ContextCompat.checkSelfPermission(activity: PermissionActivity, permission: str) -> int: ...
def ActivityCompat.request_permissions(activity: PermissionActivity, permissions: List[str], requestCode: int) -> None: ...
def ActivityCompat.should_show_request_permission_rationale(activity: PermissionActivity, permission: str) -> bool: ...

class PermissionsUtil:
    @staticmethod
    def get_permission_listener(requestCode: int) -> Optional[OnPermissionListener]: ...
