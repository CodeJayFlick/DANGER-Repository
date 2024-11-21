from concurrent.futures import Future
import typing as t

class GadpClientTargetFocusScope:
    def request_focus(self, obj: 'GadpClientTargetObject') -> Future[t.Any]:
        self._assert_valid()
        if not PathUtils.is_ancestor(self.get_path(), obj.get_path()):
            raise DebuggerIllegalArgumentException("Can only focus a successor of the scope")
        return self.send_checked(Gadp.FocusRequest(
                path=GadpValueUtils.make_path(self.get_path()),
                focus=GadpValueUtils.make_path(obj.get_path())),
                                 Gadp.FocusReply.getDefaultInstance())

    def _assert_valid(self):
        pass

    def get_delegate(self) -> t.Any:
        raise NotImplementedError("getDelegate")

    def get_model(self) -> t.Any:
        raise NotImplementedError("getModel")

    def send_checked(self, request: 'Gadp', reply_type: type['Gadp']) -> Future[t.Any]:
        raise NotImplementedError("sendChecked")
