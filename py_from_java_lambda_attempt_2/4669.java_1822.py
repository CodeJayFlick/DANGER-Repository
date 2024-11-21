Here is the translation of the Java code into equivalent Python:

```Python
# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

class DWARFAttribute:
    DW_AT_sibling = 0x1
    DW_AT_location = 0x2
    DW_AT_name = 0x3
    DW_AT_ordering = 0x9
    #DW_ AT_subscr_data = 0xa;
    DW_AT_byte_size = 0xb
    DW_AT_bit_offset = 0xc
    DW_AT_bit_size = 0xd
    #DW_ AT_element_list = 0xf;
    DW_AT_stmt_list = 0x10
    DW_AT_low_pc = 0x11
    DW_AT_high_pc = 0x12
    DW_AT_language = 0x13
    #DW_ AT_member = 0x14;
    DW_AT_discr = 0x15
    DW_AT_discr_value = 0x16
    DW_AT_visibility = 0x17
    DW_AT_import = 0x18
    DW_AT_string_length = 0x19
    DW_AT_common_reference = 0x1a
    DW_AT_comp_dir = 0x1b
    DW_AT_const_value = 0x1c
    DW_AT_containing_type = 0x1d
    DW_AT_default_value = 0x1e
    DW_AT_inline = 0x20
    DW_AT_is_optional = 0x21
    DW_AT_lower_bound = 0x22
    DW_AT_producer = 0x25
    DW_AT_prototyped = 0x27
    DW_AT_return_addr = 0x2a
    DW_AT_start_scope = 0x2c
    DW_AT_bit_stride = 0x2e
    DW_AT_upper_bound = 0x2f
    DW_AT_abstract_origin = 0x31
    DW_AT_accessibility = 0x32
    DW_AT_address_class = 0x33
    DW_AT_artificial = 0x34
    DW_AT_base_types = 0x35
    DW_AT_calling_convention = 0x36
    DW_AT_count = 0x37
    DW_AT_data_member_location = 0x38
    DW_AT_decl_column = 0x39
    DW_AT_decl_file = 0x3a
    DW_AT_decl_line = 0x3b
    DW_AT_declaration = 0x3c
    DW_AT_discr_list = 0x3d
    DW_AT_encoding = 0x3e
    DW_AT_external = 0x3f
    DW_AT_frame_base = 0x40
    DW_AT_friend = 0x41
    DW_AT_identifier_case = 0x42
    DW_AT_macro_info = 0x43
    DW_AT_name_list_item = 0x44
    DW_AT_priority = 0x45
    DW_AT_segment = 0x46
    DW_AT_specification = 0x47
    DW_AT_static_link = 0x48
    DW_AT_type = 0x49
    DW_AT_use_location = 0x4a
    DW_AT_variable_parameter = 0x4b
    DW_AT_virtuality = 0x4c
    DW_AT_vtable_elem_location = 0x4d
    DW_AT_allocated = 0x4e
    DW_AT_associated = 0x4f
    DW_AT_data_location = 0x50
    DW_AT_byte_stride = 0x51
    DW_AT_entry_pc = 0x52
    DW_AT_use_UTF8 = 0x53
    DW_AT_extension = 0x54
    DW_AT_ranges = 0x55
    DW_AT_trampoline = 0x56
    DW_AT_call_column = 0x57
    DW_AT_call_file = 0x58
    DW_AT_call_line = 0x59
    DW_AT_description = 0x5a
    DW_AT_binary_scale = 0x5b
    DW_AT_decimal_scale = 0x5c
    DW_AT_small = 0x5d
    DW_AT_decimal_sign = 0x5e
    DW_AT_digit_count = 0x5f
    DW_AT_picture_string = 0x60
    DW_AT_mutable = 0x61
    DW_AT_threads_scaled = 0x62
    DW_AT_explicit = 0x63
    DW_AT_object_pointer = 0x64
    DW_AT_endianity = 0x65
    DW_AT_elemental = 0x66
    DW_AT_pure = 0x67
    DW_AT_recursive = 0x68
    DW_AT_signature = 0x69
    DW_AT_main_subprogram = 0x6a
    DW_AT_data_bit_offset = 0x6b
    DW_AT_const_expr = 0x6c
    DW_AT_enum_class = 0x6d
    DW_AT_linkage_name = 0x6e
    DW_AT_string_length_bit_size = 0x6f
    DW_AT_string_length_byte_size = 0x70
    DW_AT_rank = 0x71
    DW_AT_str_offsets_base = 0x72
    DW_AT_addr_base = 0x73
    DW_AT_rnglists_base = 0x74

    # reserved, unused
    DW_AT_dwo_name = 0x76
    DW_AT_reference = 0x77
    DW_AT_rvalue_reference = 0x78
    DW_AT_macros = 0x79
    DW_AT_call_all_calls = 0x7a
    DW_AT_call_all_source_calls = 0x7b
    DW_AT_call_all_tail_calls = 0x7c
    DW_AT_call_return_pc = 0x7d
    DW_AT_call_value = 0x7e
    DW_AT_call_origin = 0x7f
    DW_AT_call_parameter = 0x80
    DW_AT_call_pc = 0x81
    DW_AT_call_tail_call = 0x82
    DW_AT_call_target = 0x83
    DW_AT_call_target_clobbered = 0x84
    DW_AT_call_data_location = 0x85
    DW_AT_call_data_value = 0x86

    @staticmethod
    def toString(value):
        return str(value)
```

This Python code defines a class `DWARFAttribute` with several constants and methods. The method `toString()` is used to convert the given value into string format, similar to how it was done in Java using the `toString()` method.