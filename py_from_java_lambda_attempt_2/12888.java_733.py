Here is a simple translation of your Java code into Python:

```Python
class MSP430XAssemblyTest:
    def get_language_id(self):
        return "TI_ MSP430X:LE:32:default"

    def test_assemble_moav0x8msp_r12(self):
        self.assert_one_compat_rest_exact("MOVA 0x8(SP),R12", "3c:01:08:00", "80:00:00:00", 0x00007658, 
                                          "MOVA 0x8(SP),R12")

    def test_assemble_rpt0x8_b_rlax_w_r14(self):
        self.assert_one_compat_rest_exact("RPT #0x8 { RLAX.W R14}", "47:18:0e:5e", "80:00:00:00", 0x00007894, 
                                          "RPT #0x8 { RLAX.W R14}")

    def test_assemble_mov_w_0_0xcmsp(self):
        self.assert_one_compat_rest_exact("MOV.W #0,0xc(SP)", "81:43:0c:00", "MOV.W #0,0xc(SP)", 
                                          "MOV.W #0x0,0xc(SP)")

    def assert_one_compat_rest_exact(self, assemble_code, expected_output1, expected_output2, result_value, description):
        pass  # You would need to implement this method
```

Please note that the `assert_one_compat_rest_exact` method is not implemented in Python as it was a part of JUnit testing framework.