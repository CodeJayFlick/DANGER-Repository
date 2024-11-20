class BootImageAnalyzer:
    def __init__(self):
        self.message_log = None

    def get_name(self):
        return "Android Boot, Recovery, or Vendor Image Annotation"

    def get_default_enablement(self, program):
        return False

    def get_description(self):
        return "Annotates Android Boot, Recovery, or Vendor Image files."

    def can_analyze(self, program):
        try:
            if BootImageUtil.is_boot_image(program) or BootImageUtil.is_vendor_boot_image(program):
                return True
        except Exception as e:
            pass  # not a boot image

        return False

    def is_prototype(self):
        return True

    def analyze(self, program, address_set_view, task_monitor, message_log):
        self.message_log = message_log
        auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
        if auto_analysis_manager.schedule_worker(self, None, False, task_monitor):
            return True
        else:
            return False

    def analysis_worker_callback(self, program, worker_context, task_monitor):
        address = program.min_address()

        byte_provider = MemoryByteProvider(program.memory(), address)
        binary_reader = BinaryReader(byte_provider, True)

        if BootImageUtil.is_boot_image(program):
            header = BootImageHeaderFactory.get_boot_image_header(binary_reader)

            if not (header.magic == BootImageConstants.BOOT_MAGIC):
                return False

            header_data_type = header.to_data_type()
            data = create_data(program, address, header_data_type)
            if data is None:
                self.message_log.append_msg("Unable to create header data.")
                return False

            create_fragment(program, header_data_type.name(), program.min_address(),
                            program.max_address())

            if header.kernel_size > 0:
                start = program.to_addr(header.kernel_offset())
                end = program.to_addr(header.kernel_offset() + header.kernel_size())
                create_fragment(program, BootImageConstants.KERNEL, start, end)

            if header.ramdisk_size > 0:
                start = program.to_addr(header.ramdisk_offset())
                end = program.to_addr(header.ramdisk_offset() + header.ramdisk_size())
                create_fragment(program, BootImageConstants.RAMDISK, start, end)

            if header.second_size > 0:
                start = program.to_addr(header.second_offset())
                end = program.to_addr(header.second_offset() + header.second_size())
                create_fragment(program, BootImageConstants.SECOND_STAGE, start, end)

            change_data_settings(program, task_monitor)
        elif BootImageUtil.is_vendor_boot_image(program):
            vendor_header = VendorBootImageHeaderFactory.get_vendor_boot_image_header(binary_reader)

            if not (vendor_header.magic == BootImageConstants.VENDOR_BOOT_MAGIC):
                return False

            header_data_type = vendor_header.to_data_type()
            data = create_data(program, address, header_data_type)
            if data is None:
                self.message_log.append_msg("Unable to create header data.")

            create_fragment(program, header_data_type.name(), program.min_address(),
                            program.max_address())

            if vendor_header.vendor_ramdisk_size > 0:
                start = program.to_addr(vendor_header.vendor_ramdisk_offset())
                end = program.to_addr(
                    vendor_header.vendor_ramdisk_offset() + vendor_header.vendor_ramdisk_size())
                create_fragment(program, BootImageConstants.RAMDISK, start, end)

            if vendor_header.dtb_size > 0:
                start = program.to_addr(vendor_header.dtb_offset())
                end = program.to_addr(vendor_header.dtb_offset() + vendor_header.dtb_size())
                create_fragment(program, BootImageConstants.DTB, start, end)
        else:
            return False

        remove_empty_fragments(program)

        return True

    def get_worker_name(self):
        return "BootImageAnalyzer"
