class GlobalDataHLMSMsSymbol:
    PDB_ID = 0x1151

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def data_slot(self):
        return (self.internals).data_slot()

    @property
    def texture_slot_start(self):
        return (self.internals).texture_slot_start()

    @property
    def sampler_slot_start(self):
        return (self.internals).sampler_slot_start()

    @property
    def uav_slot_start(self):
        return (self.internals).uav_slot_start()

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "GDATA_HLSL"
