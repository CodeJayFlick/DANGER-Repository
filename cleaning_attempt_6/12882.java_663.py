class AVR8AssemblyTest:
    def get_language_id(self):
        return "avr8:LE:16:extended"

    def test_assemble_out_RAMPZ_R16(self):
        self.assert_one_compat_rest_exact("out RAMPZ, R16", "0b:bf", 2 * 0x000007)

    def test_assemble_ldi_R17_0x25(self):
        self.assert_one_compat_rest_exact("ldi R17, 0x25", "15:e2", 2 * 0x000000)

    def test_assemble_inc_R16(self):
        self.assert_one_compat_rest_exact("inc R16", "03:95", 2 * 0x000006)

    def test_assemble_SKIP_add_R0_R22(self):
        self.assert_one_compat_rest_exact("add R0, R22", "06:0e", "80:00:00:00", 2 * 0x006f6c, "add R0, R22")

    def test_assemble_brbs_0xc_Cflg(self):
        self.assert_one_compat_rest_exact("brbs 0xc, Cflg", "c8:f3", 2 * 0x0000c)

    def test_assemble_lds_R18_0x019d(self):
        self.assert_one_compat_rest_exact("lds R18, 0x019d", "20:91:9d:01", 2 * 0x00012f)

    def test_assemble_call_0x256(self):
        self.assert_one_compat_rest_exact("call 0x256", "0e:94:2b:01", 2 * 0x0001ec)

    def test_assemble_com_Wlo(self):
        self.assert_one_compat_rest_exact("com Wlo", "80:95", 2 * 0x006fba)
