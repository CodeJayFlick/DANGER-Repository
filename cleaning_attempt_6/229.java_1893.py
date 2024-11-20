class JdiDalvikDebuggerMappingOpinion:
    LANG_ID_DALVIK = {"name": "Dalvik:LE:32:default", "language_id": 0}
    COMP_ID_VS = {"compiler_spec_id": 0, "name": "default"}
    DALVIK_VM_NAMES = ["Dalvik"]

    class DalvikDebuggerTargetTraceMapper:
        def __init__(self, target, langID, csId, extraRegNames):
            pass

        def create_memory_mapper(self, memory):
            return DefaultDebuggerMemoryMapper(LANG_ID_DALVIK["language_id"], memory)

        def create_register_mapper(self, registers):
            return DefaultDebuggerRegisterMapper(COMP_ID_VS["compiler_spec_id"], registers, False)


    class DalvikDebuggerMappingOffer:
        def __init__(self, process):
            super().__init__(process, 100, "Dalvik Virtual Machine", LANG_ID_DALVIK, COMP_ID_VS, set())

        def create_mapper(self):
            return DalvikDebuggerTargetTraceMapper(None, LANG_ID_DALVIK["language_id"], COMP_ID_VS["compiler_spec_id"], set())


    @staticmethod
    def contains_recognized_jvm_name(name):
        for vm in DALVIK_VM_NAMES:
            if name.lower().contains(vm.lower()):
                return True
        return False


    def offers_for_env(self, env, process, include_overrides):
        if "Java Debug Interface" not in str(env.get_debugger()):
            return set()
        if self.contains_recognized_jvm_name(str(process.get_architecture())):
            return {DalvikDebuggerMappingOffer(process)}
        else:
            return set()

