class DebuggerModelTestUtils:
    def arr(self, hex: str) -> bytes:
        return NumericUtilities.convert_string_to_bytes(hex)

    @staticmethod
    def cast(type: type, obj):
        if not isinstance(obj.get_schema(), type):
            raise AssertionError("Invalid schema")
        return type.cast(obj)

    @staticmethod
    def ancestor(type: type, seed: object) -> object:
        try:
            return DebugModelConventions.ancestor(type, seed)
        except Exception as e:
            raise AssertionError(e)

    def access(self, obj: object) -> AsyncAccess:
        try:
            return AsyncAccess(ancestor(TargetAccessConditioned, Objects.requireNonNull(obj)))
        except Exception as e:
            raise AssertionError(e)

    def wait_acc(self, acc: AsyncReference[bool]) -> None:
        self.wait_on(acc.wait_value(True))

    @staticmethod
    def cli(interpreter: object, cmd: str) -> str:
        try:
            return interpreter.as(TargetInterpreter).execute(cmd)
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def capture_cli(interpreter: object, cmd: str) -> str:
        try:
            return interpreter.as(TargetInterpreter).execute_capture(cmd)
        except Exception as e:
            raise AssertionError(e)

    def launch(self, launcher: object, args: dict) -> None:
        try:
            self.wait_on(launcher.as(TargetLauncher).launch(args))
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def resume(resumable: object) -> None:
        try:
            resumable.as(TargetResumable).resume()
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def step(steppable: object, kind: TargetStepKind) -> None:
        try:
            steppable.as(TargetSteppable).step(kind)
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def get_focus(scope: object) -> object:
        return scope.as(TargetFocusScope).get_focus()

    @staticmethod
    def focus(self, scope: object, focus: object) -> None:
        try:
            self.wait_on(scope.as(TargetFocusScope).request_focus(focus))
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def hexlify(map: dict) -> dict:
        return {k: NumericUtilities.convert_bytes_to_string(v) for k, v in map.items()}

    @staticmethod
    def assert_unique_shortest(refs: NavigableMap):
        if not refs.size() >= 1:
            raise AssertionError("No references found")
        shortest = next(iter(refs))
        if not rit.hasNext():
            return shortest.get()
        next_entry = next(iter(refs))
        if next_entry.key().size > shortest.key().size:
            raise AssertionError(f"Shortest is not unique: {refs}")
        return shortest.get()

    @staticmethod
    def get_attachable(attachables, specimen, dummy, test) -> object:
        try:
            return next((a for a in attachables if specimen.is_attachable(dummy, a, test)), None)
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def get_process_running(processes: list, specimen, test):
        return get_process_running(processes, specimen, test, lambda p: True)

    @staticmethod
    def get_process_running(processes: list, specimen, test, predicate) -> object:
        try:
            return next((p for p in processes if predicate(p) and specimen.is_running_in(p, test)), None)
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def fetch_processes(test):
        try:
            return [(k, v) for k, v in test.m.find_all(TargetProcess).values()]
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def retry_for_process_running(specimen: object, test: object) -> object:
        process = None
        while True:
            try:
                process = get_process_running(specimen, test)
                if process is not None and isinstance(process, TargetProcess):
                    return process
            except Exception as e:
                raise AssertionError(e)

    @staticmethod
    def retry_for_other_process_running(specimen: object, test: object, predicate) -> object:
        try:
            while True:
                process = get_process_running(specimen, test, predicate)
                if process is not None and isinstance(process, TargetProcess):
                    return process
        except Exception as e:
            raise AssertionError(e)

    def wait_settled(self, model: DebuggerObjectModel, ms) -> None:
        debouncer = AsyncDebouncer(Void(), ms)
        listener = DebuggerModelListener()
        try:
            model.add_model_listener(listener)
            debouncer.contact(None)
            self.wait_on_no_validate(debouncer.settled())
        except Exception as e:
            raise AssertionError(e)

    def wait_settled(self, model: DebuggerObjectModel) -> None:
        self.wait_settled(model, 1000)
