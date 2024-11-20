class MergeProgramGeneratorCalcs:
    def __init__(self, consumer):
        self.consumer = consumer
        self.last_generated_universal_id = None

    def generate_program(self, program_name: str) -> dict:
        if program_name == "calc.exe":
            return self.build_calc_exe_program()
        elif program_name == "overlayCalc":
            return self.build_overlay_calc_exe_program()
        else:
            raise Exception(f"Add new builder for program: {program_name}")

    def build_calc_exe_program(self) -> dict:
        program = {
            ".text": {"start_address": 0x1001000, "size": 12600},
            ".data": [{"start_address": 0x1014000, "size": 0xc00}, 
                      {"start_address": 0x10150bf, "size": 0x4c0}],
            ".rsrc": {"start_address": 0x1018bff, "size": 0x2c00}
        }
        
        program["DATE_CREATED"] = datetime.date(100000000)

        return program

    def build_overlay_calc_exe_program(self) -> dict:
        program = {
            ".text": {"start_address": 0x1001000, "size": 12600},
            ".data": [{"start_address": 0x1014000, "size": 0xc00}, 
                      {"start_address": 0x10150bf, "size": 0x4c0}],
            ".rsrc": {"start_address": 0x1018bff, "size": 0x2c00},
            "TextOverlay": {"start_address": 0x01001630, "size": 200}
        }
        
        program["DATE_CREATED"] = datetime.date(100000000)

        return program
