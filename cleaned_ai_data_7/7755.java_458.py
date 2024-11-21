import ghidra_app_script as GAS

class IdPeRttiScript(GAS.GhidraScript):
    def run(self):
        if not self.current_program:
            print("There is no open program.")
            return
        
        if not self.is_running_headless():
            print("The current program does not appear to contain RTTI.")
            return
        else:
            self.current_program.set_temporary(True)
            return

        pe = GAS.PEUtil().is_visual_studio_or_clang_pe(self.current_program)
        if not pe:
            if not self.is_running_headless():
                print("The current program is not a Visual Studio or Clang PE program.")
                return
            else:
                self.current_program.set_temporary(True)
                return

        common_vf_table_address = GAS.RttiUtil().find_type_info_vftable_address(self.current_program, None)

        if not common_vf_table_address:
            if not self.is_running_headless():
                print("The current program does not appear to contain RTTI.")
                return
            else:
                self.current_program.set_temporary(True)
                return

        if not self.is_running_headless():
            print("The current program is a Visual Studio PE or Clang that contains RTTI.")
            return
        else:
            self.current_program.set_temporary(False)

# Usage: 
script = IdPeRttiScript()
try:
    script.run()
except Exception as e:
    print(f"An error occurred: {e}")
