Here is the translation of the given Java code into equivalent Python:

```Python
class GdbModelTargetStack:
    def __init__(self, thread: 'GdbThread', inferior: 'GdbInferior') -> None:
        self.impl = thread.impl
        self.inferior = inferior
        self.thread = thread

    @property
    def name(self) -> str:
        return "Stack"

    def request_elements(self, refresh: bool) -> CompletableFuture[None]:
        future = self.thread.list_stack_frames()
        future.then_accept(lambda f: 
            frames = list(map(self.get_target_frame, f))
            set_elements(frames, 'Refreshed')
        )
        return future

    def get_target_frame(self, frame: 'GdbStackFrame') -> 'GdbModelTargetStackFrame':
        level = frame.level
        if not self.frames_by_level:
            for i in range(level):
                self.frames_by_level[i] = GdbModelTargetStackFrame(self, None, self.inferior, None)
        return self.frames_by_level[level - 1]

    def get_target_frame_by_level(self, level: int) -> 'GdbModelTargetStackFrame':
        if not self.frames_by_level:
            for i in range(level):
                self.frames_by_level[i] = GdbModelTargetStackFrame(self, None, self.inferior, None)
        return self.frames_by_level[level - 1]

    def invalidate_register_caches(self) -> None:
        for frame in self.frames_by_level.values():
            frame.invalidate_register_caches()

    async def state_changed(self, sco: 'GdbStateChangeRecord') -> CompletableFuture[None]:
        future = self.request_elements(True)
        innermost_frame = self.get_target_frame_by_level(0)
        if innermost_frame:
            return await innermost_frame.state_changed(sco)
        else:
            return AsyncUtils.NIL
        except Exception as e:
            self.impl.report_error(self, f"Could not update stack {self} on STOPPED", e)

    @property
    def frames_by_level(self) -> dict[int, 'GdbModelTargetStackFrame']:
        if not hasattr(self, '_frames_by_level'):
            self._frames_by_level = {}
        return self._frames_by_level

class GdbThread:
    pass

class GdbInferior:
    pass

class GdbStateChangeRecord:
    pass
```

Note: Python does not have direct equivalent of Java's `CompletableFuture` and `WeakValueHashMap`. The above code uses the built-in `async/await` syntax for asynchronous programming, but it is different from what you would use in a Java program.