class InjectPayloadCallotherError:
    def __init__(self, addr_factory: 'AddressFactory', failed_payload):
        super().__init__(InjectPayloadSleigh.get_dummy_pcode(addr_factory), failed_payload)

    def __init__(self, addr_factory: 'AddressFactory', nm: str):
        super().__init__(InjectPayloadSleigh.get_dummy_pcode(addr_factory), nm)

    def isErrorPlaceholder(self) -> bool:
        return True
