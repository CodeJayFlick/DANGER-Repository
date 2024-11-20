Here is the translation of the given Java code into Python:

```Python
class AVR32AssemblyTest:
    def get_language_id(self):
        return "avr32:BE:32:default"

    def test_assemble_br_ls_0x00003dae(self):
        self.assert_one_compat_rest_exact("BR{ls} 0x00003dae", "fe:98:ff:e5", 0x00003de4)

    def test_assemble_stm_nn_sp_r7_lr(self):
        self.assert_one_compat_rest_exact("STM --SP, R7, LR", "eb:cd:40:80")

if __name__ == "__main__":
    avr32_assembly_test = AVR32AssemblyTest()
    avr32_assembly_test.get_language_id()
    avr32_assembly_test.test_assemble_br_ls_0x00003dae()
    avr32_assembly_test.test_assemble_stm_nn_sp_r7_lr()

```

Please note that Python does not have direct equivalent of Java's JUnit testing framework. The above code is a simple translation and may need to be modified based on the actual requirements.