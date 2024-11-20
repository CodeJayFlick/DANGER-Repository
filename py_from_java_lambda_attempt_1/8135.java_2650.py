Here is the translation of the Java code into Python:

```Python
class Compile3MsSymbol:
    PDB_ID = 0x113c

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.process_flags(reader.parse_unsigned_int_val())
        self.processor = Processor.from_value(reader.parse_unsigned_short_val())
        self.front_end_major_version_number = reader.parse_unsigned_short_val()
        self.front_end_minor_version_number = reader.parse_unsigned_short_val()
        self.front_end_build_version_number = reader.parse_unsigned_short_val()
        self.front_end_quick_fix_engineering_version_number = reader.parse_unsigned_short_val()
        self.back_end_major_version_number = reader.parse_unsigned_short_val()
        self.back_end_minor_version_number = reader.parse_unsigned_short_val()
        self.back_end_build_version_number = reader.parse_unsigned_short_val()
        self.back_end_quick_fix_engineering_version_number = reader.parse_unsigned_short_val()
        self.compiler_version_string = reader.parse_string(pdb, 'StringUtf8Nt')

    def get_pdb_id(self):
        return self.PDB_ID

    @property
    def language(self):
        return self._language.toString()

    @property
    def compiled_for_edit_and_continue(self):
        return self._compiled_for_edit_and_continue

    @property
    def not_compiled_with_debug_info(self):
        return self._not_compiled_with_debug_info

    @property
    def compiled_with_link_time_code_generation(self):
        return self._compiled_with_link_time_code_generation

    @property
    def compiled_with_bzalign_no_data_align(self):
        return self._compiled_with_bzalign_no_data_align

    @property
    def managed_code_data_present(self):
        return self._managed_code_data_present

    @property
    def compiled_with_gs_buffer_security_checks(self):
        return self._compiled_with_gs_buffer_security_checks

    @property
    def compiled_with_hot_patch(self):
        return self._compiled_with_hot_patch

    @property
    def converted_with_cvtcil(self):
        return self._converted_with_cvtcil

    @property
    def microsoft_intermediate_language_net_module(self):
        return self._microsoft_intermediate_language_net_module

    @property
    def compiled_with_sdl(self):
        return self._compiled_with_sdl

    @property
    def compiled_with_ltcg_pgo_or_pgu(self):
        return self._compiled_with_ltcg_pgo_or_pgu

    @property
    def dot_exp_module(self):
        return self._dot_exp_module

    @property
    def processor(self):
        return self._processor

    @property
    def front_end_major_version_number(self):
        return self._front_end_major_version_number

    @property
    def front_end_minor_version_number(self):
        return self._front_end_minor_version_number

    @property
    def front_end_build_version_number(self):
        return self._front_end_build_version_number

    @property
    def front_end_quick_fix_engineering_version_number(self):
        return self._front_end_quick_fix_engineering_version_number

    @property
    def back_end_major_version_number(self):
        return self._back_end_major_version_number

    @property
    def back_end_minor_version_number(self):
        return self._back_end_minor_version_number

    @property
    def back_end_build_version_number(self):
        return self._back_end_build_version_number

    @property
    def back_end_quick_fix_engineering_version_number(self):
        return self._back_end_quick_fix_engineering_version_number

    @property
    def compiler_version_string(self):
        return self._compiler_version_string

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}:")
        builder.append(f"  Language: {self.language}")
        builder.append(f"  Target Processor: {self.processor}")

        if self.compiled_for_edit_and_continue:
            builder.append("   Compiled for edit and continue: yes")
        else:
            builder.append("   Compiled for edit and continue: no")

        if not self.not_compiled_with_debug_info:
            builder.append("   Compiled without debugging info: yes")
        else:
            builder.append("   Compiled without debugging info: no")

        if self.compiled_with_link_time_code_generation:
            builder.append(f"   Compiled with LTCG: {self._compiled_with_link_time_code_generation}")
        else:
            builder.append("   Compiled with LTCG: no")

        if self.compiled_with_bzalign_no_data_align:
            builder.append(f"   Compiled with /bzalign: {self._compiled_with_bzalign_no_data_align}")
        else:
            builder.append("   Compiled with /bzalign: no")

        if self.managed_code_data_present:
            builder.append("   Managed code present: yes")
        else:
            builder.append("   Managed code present: no")

        if self.compiled_with_gs_buffer_security_checks:
            builder.append(f"   Compiled with /GS: {self._compiled_with_gs_buffer_security_checks}")
        else:
            builder.append("   Compiled with /GS: no")

        if self.compiled_with_hot_patch:
            builder.append(f"   Compiled with /hotpatch: {self._compiled_with_hot_patch}")
        else:
            builder.append("   Compiled with /hotpatch: no")

        if self.converted_with_cvtcil:
            builder.append(f"   Converted by CVTCIL: {self._converted_with_cvtcil}")
        else:
            builder.append("   Converted by CVTCIL: no")

        if self.microsoft_intermediate_language_net_module:
            builder.append(f"   Microsoft Intermediate Language Module: {self._microsoft_intermediate_language_net_module}")
        else:
            builder.append("   Microsoft Intermediate Language Module: no")

        if self.compiled_with_sdl:
            builder.append(f"   Compiled with /sdl: {self._compiled_with_sdl}")
        else:
            builder.append("   Compiled with /sdl: no")

        if self.compiled_with_ltcg_pgo_or_pgu:
            builder.append(f"   Compiled with Profile Guided Optimization (PGO): {self._compiled_with_ltcg_pgo_or_pgu}")
        else:
            builder.append("   Compiled with Profile Guided Optimization (PGO): no")

        if self.dot_exp_module:
            builder.append(f".EXP module: yes")
        else:
            builder.append(".EXP module: no")

        builder.append(
            f"  Frontend Version: Major = {self.front_end_major_version_number}, Minor = {self.front_end_minor_version_number}, Build = {self.front_end_build_version_number}, QFE = {self.front_end_quick_fix_engineering_version_number}"
        )
        builder.append(
            f"  Backend Version: Major = {self.back_end_major_version_number}, Minor = {self.back_end_minor_version_number}, Build = {self.back_end_build_version_number}, QFE = {self.back_end_quick_fix_engineering_version_number}"
        )
        builder.append(f"   Version String: {self.compiler_version_string}")

    def get_symbol_type_name(self):
        return "COMPILE3"

    @staticmethod
    def process_flags(flags_in):
        language_value = flags_in & 0xff
        flags_in >>= 8

        compiled_for_edit_and_continue = (flags_in & 1) == 1
        flags_in >>= 1
        not_compiled_with_debug_info = (flags_in & 1) == 1
        flags_in >>= 1
        compiled_with_link_time_code_generation = (flags_in & 1) == 1
        flags_in >>= 1
        compiled_with_bzalign_no_data_align = (flags_in & 1) == 1
        flags_in >>= 1
        managed_code_data_present = (flags_in & 1) == 1
        flags_in >>= 1
        compiled_with_gs_buffer_security_checks = (flags_in & 1) == 1
        flags_in >>= 1
        compiled_with_hot_patch = (flags_in & 1) == 1
        flags_in >>= 1
        converted_with_cvtcil = (flags_in & 1) == 1
        flags_in >>= 1
        microsoft_intermediate_language_net_module = (flags_in & 1) == 1
        flags_in >>= 1
        compiled_with_sdl = (flags_in & 1) == 1
        flags_in >>= 1
        compiled_with_ltcg_pgo_or_pgu = (flags_in & 1) == 1
        flags_in >>= 1
        dot_exp_module = (flags_in & 1) == 1

    @property
    def _language(self):
        pass

    @property
    def _compiled_for_edit_and_continue(self):
        return False

    @property
    def _not_compiled_with_debug_info(self):
        return True

    @property
    def _compiled_with_link_time_code_generation(self):
        return False

    @property
    def _compiled_with_bzalign_no_data_align(self):
        return False

    @property
    def _managed_code_data_present(self):
        return False

    @property
    def _compiled_with_gs_buffer_security_checks(self):
        return False

    @property
    def _compiled_with_hot_patch(self):
        return False

    @property
    def _converted_with_cvtcil(self):
        return False

    @property
    def _microsoft_intermediate_language_net_module(self):
        return False

    @property
    def _compiled_with_sdl(self):
        return False

    @property
    def _compiled_with_ltcg_pgo_or_pgu(self):
        return False

    @property
    def _dot_exp_module(self):
        return False

    @property
    def _processor(self):
        pass

    @property
    def _front_end_major_version_number(self):
        pass

    @property
    def _front_end_minor_version_number(self):
        pass

    @property
    def _front_end_build_version_number(self):
        pass

    @property
    def _front_end_quick_fix_engineering_version_number(self):
        pass

    @property
    def _back_end_major_version_number(self):
        pass

    @property
    def _back_end_minor_version_number(self):
        pass

    @property
    def _back_end_build_version_number(self):
        pass

    @property
    def _back_end_quick_fix_engineering_version_number(self):
        pass

    @property
    def _compiler_version_string(self):
        pass