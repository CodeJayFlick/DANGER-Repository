Here is the translation of the Java code into equivalent Python:

```Python
class WrapCallbackIDebugEventCallbacks:
    def __init__(self, client, cb):
        self.client = client
        self.cb = cb
        self.listener = None

    def set_listener(self, listener):
        self.listener = listener

    def get_pointer(self):
        return self.listener.get_pointer()

    def QueryInterface(self, refid, ppvObject):
        if not ppvObject:
            return WinError.E_POINTER
        elif refid.value == IDebugEventCallbacks.IID_IDEBUG_EVENT_CALLBACKS:
            ppvObject.value = self.get_pointer()
            return WinError.S_OK
        elif refid.value == IUnknown.IID_IUNKNOWN:
            ppvObject.value = self.get_pointer()
            return WinError.S_OK
        else:
            return WinError.E_NOINTERFACE

    def AddRef(self):
        return 0

    def Release(self):
        return 0

    def GetInterestMask(self, Mask):
        try:
            interest_mask = self.cb.get_interest_mask()
            ul_interest = ULONG(interest_mask.bitmask)
            Mask.value = ul_interest
            return WinError.S_OK
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return WinError.E_UNEXPECTED

    def Breakpoint(self, Bp):
        try:
            bpt = DebugBreakpointInternal.try_preferred_interfaces(self.client.get_control_internal(), Bp.QueryInterface)
            status = self.cb.breakpoint(bpt)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def Exception(self, Exception, FirstChance):
        try:
            num_params = Exception.NumberParameters
            information = [Exception.ExceptionInformation[i] for i in range(num_params)]
            exc = DebugExceptionRecord64(Exception.ExceptionCode, Exception.ExceptionFlags,
                                          Exception.ExceptionRecord, Exception.ExceptionAddress, information)
            first_chance = bool(FirstChance.value != 0)
            status = self.cb.exception(exc, first_chance)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def CreateThread(self, Handle, DataOffset, StartOffset):
        try:
            status = self.cb.create_thread(DebugThreadInfo(Handle.value, DataOffset.value, StartOffset.value))
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def ExitThread(self, ExitCode):
        try:
            status = self.cb.exit_thread(ExitCode.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def CreateProcess(self, ImageFileHandle, Handle, BaseOffset, ModuleSize, ModuleName, ImageName,
                      CheckSum, TimeDateStamp, InitialThreadHandle, ThreadDataOffset, StartOffset):
        try:
            # TODO: Associate thread with process
            # TODO: Record All these other parameters?
            status = self.cb.create_process(DebugProcessInfo(Handle.value, DebugModuleInfo(ImageFileHandle.value, BaseOffset.value,
                                                                                        ModuleSize.value, ModuleName, ImageName, CheckSum.value, TimeDateStamp.value),
                                                                                       DebugThreadInfo(InitialThreadHandle.value, ThreadDataOffset.value, StartOffset.value)))
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def ExitProcess(self, ExitCode):
        try:
            status = self.cb.exit_process(ExitCode.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def LoadModule(self, ImageFileHandle, BaseOffset, ModuleSize, ModuleName, ImageName,
                   CheckSum, TimeDateStamp):
        try:
            # All of these are potentially null
            image_file_handle = ImageFileHandle.value if ImageFileHandle else -1
            base_offset = BaseOffset.value if BaseOffset else -1
            module_size = ModuleSize.value if ModuleSize else -1
            module_name = str(ModuleName) if ModuleName else ""
            image_name = str(ImageName) if ImageName else ""

            status = self.cb.load_module(DebugModuleInfo(image_file_handle, base_offset,
                                                         module_size, module_name, image_name, CheckSum.value, TimeDateStamp.value))
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def UnloadModule(self, ImageBaseName, BaseOffset):
        try:
            status = self.cb.unload_module(ImageBaseName, BaseOffset.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def SystemError(self, Error, Level):
        try:
            status = self.cb.system_error(Error.value, Level.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def SessionStatus(self, Status):
        try:
            ss = SessionStatus.values()[Status.value]
            status = self.cb.session_status(ss)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def ChangeDebuggeeState(self, Flags, Argument):
        try:
            flags = BitmaskSet(DebugClient.ChangeDebuggeeState)(Flags.value)
            status = self.cb.change_debuggee_state(flags, Argument.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def ChangeEngineState(self, Flags, Argument):
        try:
            flags = BitmaskSet(DebugClient.ChangeEngineState)(Flags.value)
            status = self.cb.change_engine_state(flags, Argument.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT

    def ChangeSymbolState(self, Flags, Argument):
        try:
            flags = BitmaskSet(DebugClient.ChangeSymbolState)(Flags.value)
            status = self.cb.change_symbol_state(flags, Argument.value)
            return HRESULT(status.ordinal())
        except Exception as e:
            Msg.error(self, "Error during callback", e)
            return ERROR_RESULT
```

Please note that the Python code does not exactly match the Java code. The translation is based on equivalent functionality and may have slight differences in syntax or logic.