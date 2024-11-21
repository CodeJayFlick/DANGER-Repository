class CpuTypes:
    CPU_ARCH_MASK = 0xff000000
    CPU_ARCH_ABI64 = 0x01000000
    
    CPU_TYPE_ANY = -1
    CPU_TYPE_VAX = 1
    # UNUSED                                     2
    # UNUSED                                     3
    # UNUSED                                     4
    # UNUSED                                     5
    CPU_TYPE_MC680X0 = 6
    CPU_TYPE_X86 = 7
    CPU_TYPE_I386 = CPU_TYPE_X86         # compatibility 
    # CPU_TYPE_MIPS                              8 
    # UNUSED                                     9
    CPU_TYPE_MC98000 = 10
    CPU_TYPE_HPPA = 11
    CPU_TYPE_ARM = 12
    CPU_TYPE_MC88000 = 13
    CPU_TYPE_SPARC = 14
    CPU_TYPE_I860 = 15
    # CPU_TYPE_ALPHA                             16
    # UNUSED                                     17
    CPU_TYPE_POWERPC = 18

    CPU_TYPE_POWERPC64 = (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)
    CPU_TYPE_X86_64 = (CPU_TYPE_X86 | CPU_ARCH_ABI64)
    CPU_TYPE_ARM_64 = (CPU_TYPE_ARM | CPU_ARCH_ABI64)

    def get_processor(cpu_type, cpu_subtype):
        if cpu_type == 7:
            return "x86"
        elif cpu_type == 18:
            return "PowerPC"
        elif cpu_type == 12:
            return "ARM"
        elif cpu_type == 19: 
            return "AARCH64" # assuming this is the correct processor name for ARM_64
        else:
            raise RuntimeError(f"Unrecognized CPU type: {cpu_type}")

    def get_processor_bit_size(cpu_type):
        if cpu_type in [1, 2, 3, 4, 5]:
            return 32
        elif cpu_type == 12 or cpu_type == 19:
            return 64
        else:
            raise RuntimeError(f"Unrecognized CPU type: {cpu_type}")

    def get_magic_string(cpu_type, cpu_subtype):
        if cpu_type == 12:
            return f"{cpu_type}.{cpu_subtype}"
        else:
            return str(cpu_type)
