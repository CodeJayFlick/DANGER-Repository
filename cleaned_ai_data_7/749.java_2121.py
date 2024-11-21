from typing import List, Any

class DbgModelTargetLauncher:
    def launch(self, args: List[str]) -> Any:
        try:
            return self.get_model().gate_future(self.get_manager().launch(args))
        except Exception as e:
            raise DebuggerUserException(f"Launch failed for {args}") from e
