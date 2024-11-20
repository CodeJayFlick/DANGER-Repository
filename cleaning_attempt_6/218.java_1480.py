class GdbArmDebuggerMappingOpinion:
    def __init__(self):
        pass

    class GdbArmOffer:
        def __init__(self, target, confidence, description, lcsp, extra_reg_names):
            self.target = target
            self.confidence = confidence
            self.description = description
            self.lcsp = lcsp
            self.extra_reg_names = set(extra_reg_names)

    class GdbAArch64Offer:
        def __init__(self, target, confidence, description, lcsp, extra_reg_names):
            self.target = target
            self.confidence = confidence
            self.description = description
            self.lcsp = lcsp
            self.extra_reg_names = set(extra_reg_names)

    def offers_for_language_and_cspec(self, target, arch, endian, lcsp):
        lang_serv = DefaultLanguageService()
        desc = None
        try:
            desc = lang_serv.get_language_description(lcsp.language_id)
        except LanguageNotFoundException as e:
            raise AssertionError(e)

        proc = desc.processor.toString().upper()

        if "ARM" == proc:
            if "Cortex".casefold() in desc.variant.casefold():
                return {GdbArmOffer(target, 50, f"ARM-Cortex/GDB for {arch}", lcsp, {"cpsr"})}
            else:
                return {GdbArmOffer(target, 50, f"ARM/GDB for {arch}", lcsp, {"cpsr"})}

        if "AARCH64".casefold() == proc:
            return {GdbAArch64Offer(target, 50, f"AARCH64/GDB for {arch}", lcsp, {"cpsr"})}

        return set()
