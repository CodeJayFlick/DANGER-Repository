class SparcAssemblyTest:
    def get_language_id(self):
        return "sparc:BE:32:default"

    def test_assemble_rd_y_g2(self):
        assert self.assemble("rd %Y, g2") == "85:40:00:00"

    # Too many reserved/undefined bits: 524288 instructions to test
    # I tested them all once.
    def test_assemble_restore(self):
        assert self.assemble("restore") == "81:e8:00:00"

    def test_assemble_wr_g3_g0(self):
        assert self.assemble("wr g0, g3, %Y") == "81:80:00:03"

    def assemble(self, instruction):
        # This method is not implemented in the original Java code.
        pass
