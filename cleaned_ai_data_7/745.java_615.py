from typing import Any

class DbgModelTargetFocusScope:
    def __init__(self):
        pass

    def get_focus(self) -> Any:
        raise NotImplementedError("Must be implemented by subclass")

    def set_focus(self, sel: Any) -> bool:
        raise NotImplementedError("Must be implemented by subclass")

    async def request_focus(self, obj: Any) -> None:
        await self.get_model().gate_future(self.get_manager().request_focus(self, obj))

    async def do_request_focus(self, obj: Any) -> None:
        if self.get_manager().is_waiting():
            return

        self.get_model().assert_mine(type(obj), obj)
        if obj == self.get_focus():
            return

        if not PathUtils.is_ancestor(self.get_path(), obj.get_path()):
            raise DebuggerIllegalArgumentException("Can only focus a successor of the scope")

        cur = obj
        while cur is not None:
            if isinstance(cur, DbgModelSelectableObject):
                sel = cur  # type: ignore
                self.set_focus(sel)
                return

            if isinstance(cur, DbgModelTargetObject):
                def_ = cur  # type: ignore
                cur = def_.get_parent()
                continue

            raise AssertionError()

