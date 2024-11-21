Here is a translation of the Java interface into equivalent Python code:

```Python
from concurrent.futures import Future

class GadpClientTargetBreakpointSpec:
    def __init__(self):
        pass

    def toggle(self, enabled: bool) -> Future[None]:
        # Equivalent to getDelegate().assertValid()
        self._validate()

        # Equivalent to getModel().sendChecked(Gadp.BreakToggleRequest.newBuilder()...
        request = {'path': self.get_path(), 'enabled': enabled}
        response = self._make_request(request)
        return response.then_apply(lambda x: None)

    def disable(self) -> Future[None]:
        return self.toggle(False)

    def enable(self) -> Future[None]:
        return self.toggle(True)

    def add_action(self, action):
        # Equivalent to getDelegate().getActions(true).add(action)
        actions = self._get_actions()
        if actions is not None:
            actions.add(action)

    def remove_action(self, action):
        # Equivalent to ListenerSet<TargetBreakpointAction> actions = getDelegate().getActions(false);
        # ...actions.remove(action);...
        actions = self._get_actions(False)
        if actions is not None:
            actions.remove(action)

    def _validate(self):
        pass

    def _make_request(self, request):
        pass

    def _get_actions(self) -> list:
        return []

    def _get_actions(self, false: bool) -> list:
        return []
```

Please note that this is a direct translation of the Java code into Python. The actual implementation details (like what `_validate`, `_make_request` and `_get_actions` methods do) are not provided here as they were in the original Java code.