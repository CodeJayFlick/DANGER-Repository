class GdbPowerPCDebuggerMappingOpinion:
    LANG_ID_PPC32_BE = "PowerPC:BE:32:default"
    LANG_ID_PPC64_BE = "PowerPC:BE:64:default"
    LANG_ID_PPC64_BE_A2 = "PowerPC:BE:64:A2-32addr"
    LANG_ID_PPC64_BE_A2ALT = "PowerPC:BE:64:A2ALT-32addr"

    COMP_ID_DEFAULT = "default"

    class GdbPowerPCBE32DefLinuxOffer:
        def __init__(self, process):
            self.process = process

    class GdbPowerPCBE64DefLinuxOffer:
        def __init__(self, process):
            self.process = process

    class GdbPowerPCBE64A2LinuxOffer:
        def __init__(self, process):
            self.process = process

    class GdbPowerPCBA64A2AltLinuxOffer:
        def __init__(self, process):
            self.process = process

    def offers_for_env(self, env, process, include_overrides=False):
        if not isinstance(env.get_debugger(), str) or "gdb" not in env.get_debugger().lower():
            return set()

        os = env.get_operating_system()
        if "Linux" not in os:
            return set()

        endian = env.get_endian()
        if "big" not in endian:
            return set()

        arch = env.get_architecture()
        if arch.startswith("powerpc:32"):
            return {GdbPowerPCBE32DefLinuxOffer(process)}
        elif arch.startswith("powerpc:A2"):
            return {GdbPowerPCBE64A2LinuxOffer(process)}
        elif arch.startswith("powerpc:A2-Alt"):
            return {GdbPowerPCBA64A2AltLinuxOffer(process)}
        elif arch.startswith("powerpc"):
            return {GdbPowerPCBE64DefLinuxOffer(process)}

        return set()
