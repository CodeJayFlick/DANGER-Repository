class DefaultGdbDebuggerMappingOpinion:
    EXTERNAL_TOOL = "gnu"
    PREFERRED_CSPEC_ID = {"gcc"}

    _cache = {}

    def __init__(self):
        pass

    class GdbDefaultOffer:
        def __init__(self, target, confidence, description, lcsp, extra_reg_names):
            self.target = target
            self.confidence = confidence
            self.description = description
            self.lcsp = lcsp
            self.extra_reg_names = extra_reg_names

    @staticmethod
    def get_compiler_specs_for_gnu(arch, endian):
        if arch not in DefaultGdbDebuggerMappingOpinion._cache:
            lang_serv = DefaultLanguageService().get_language_service()
            specs = lang_serv.get_language_compiler_spec_pairs(
                ExternalLanguageCompilerSpecQuery(arch, DefaultGdbDebuggerMappingOpinion.EXTERNAL_TOOL,
                                                  endian, None, DefaultGdbDebuggerMappingOpinion.PREFERRED_CSPEC_ID[0]))
            DefaultGdbDebuggerMappingOpinion._cache[arch] = specs
        return DefaultGdbDebuggerMappingOpinion._cache[arch]

    @staticmethod
    def is_gdb(env):
        if env is None:
            return False
        if "gdb" not in str(env.get_debugger()).lower():
            return False
        return True

    @staticmethod
    def is_linux(env):
        if env is None:
            return False
        if "linux" not in str(env.get_operating_system()):
            return False
        return True

    def offers_for_language_and_cspec(self, target, arch, endian, lcsp):
        return {GdbDefaultOffer(target, 10, f"default gdb for {arch}", lcsp, {""})}

    @staticmethod
    def offers_for_env(env, process, include_overrides=False):
        if not DefaultGdbDebuggerMappingOpinion.is_gdb(env):
            return set()
        endian = env.get_endian()
        arch = str(env.get_architecture())

        specs = DefaultGdbDebuggerMappingOpinion.get_compiler_specs_for_gnu(arch, endian)
        offers = set()

        for lcsp in specs:
            offers.update(self.offers_for_language_and_cspec(process, arch, endian, lcsp))

        return offers
