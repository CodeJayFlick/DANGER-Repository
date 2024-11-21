class DefinedDataXmlMgr:
    def __init__(self, program, log):
        self.program = program
        self.log = log

    def read(self, parser, overwrite_data, monitor):
        listing = self.program.get_listing()
        address_factory = self.program.get_address_factory()
        data_type_manager = listing.get_data_type_manager()

        skip_code_unit_errors = 0

        try:
            dt_parser = DtParser(data_type_manager)

            element = parser.next()  # consume DATA start
            while True:
                if monitor.is_cancelled():
                    raise CancelledException()
                element = parser.next()
                if not element.get_name().equals("DEFINED_DATA"):
                    break
                addr_str = element.get_attribute("ADDRESS")
                if addr_str is None:
                    self.log.append_msg("Defined data: address not specified.")
                    parser.discard_subtree(element)
                    continue

                addr = XmlProgramUtilities.parse_address(address_factory, addr_str)
                if addr is None:
                    self.log.append_msg(f"Defined data: invalid address {addr_str}")
                    parser.discard_subtree(element)
                    continue

                data_type_name = element.get_attribute("DATATYPE")
                path = CategoryPath() if not element.has_attribute("DATATYPE_NAMESPACE") else CategoryPath(element.get_attribute("DATATYPE_NAMESPACE"))
                size = XmlUtilities.parseInt(element.get_attribute("SIZE")) if element.has_attribute("SIZE") else -1
                #size *= address_factory.get_default_address_space().get_addressable_unit_size()

                dt = dt_parser.parse_data_type(data_type_name, path, size)
                if dt is None:
                    self.log.append_msg(f"Defined data: unknown datatype {data_type_name} in category {path}")
                    parser.discard_subtree(element)
                    continue

                if not self.program.get_memory().contains(addr):
                    skip_code_unit_errors += 1
                    parser.discard_subtree(element)
                    continue

                try:
                    if overwrite_data:
                        self.clear_existing_data(addr, size, dt, listing)

                    data = listing.create_data(addr, dt, size)

                    # there was a problem in that we write "DISPLAY_SETTINGS" and were reading "DISPLAY_SETTING". Not knowing which is correct, just handle both in case older Ghidra versions used the other
                    if parser.peek().get_name().equals("DISPLAY_SETTING"):
                        DisplaySettingsHandler.read_settings(parser.next(), data)
                        parser.next()
                    elif parser.peek().get_name().equals("DISPLAY_SETTINGS"):
                        DisplaySettingsHandler.read_settings(parser.next(), data)
                        parser.next()

                    #TODO: handle TypeInfo comment...
                except CodeUnitInsertionException as e:
                    d = listing.get_defined_data_at(addr)
                    if d is None or not d.get_data_type().is_equivalent(dt):
                        self.log.append_msg(e.message)

                    parser.discard_subtree(element)
                    continue
                except Exception as e:
                    self.log.append_exception(e)

                    parser.discard_subtree(element)
                    continue

                parser.end_element()

            if skip_code_unit_errors != 0:
                self.log.append_msg(f"Skipped {skip_code_unit_errors} Data elements where no memory was defined")

        finally:
            built_in_mgr = data_type_manager.get_data_type_manager()
            built_in_mgr.close()

    def clear_existing_data(self, addr, size, dt, listing):
        buf = DumbMemBufferImpl(self.program.get_memory(), addr)
        dti = DataTypeInstance.get_data_type_instance(dt, buf, size)

        if dti is not None:
            do_clear = False
            max_addr = addr.add(dti.length - 1)
            code_units = listing.get_code_units(AddressSet(addr, max_addr), True)
            while code_units.has_next():
                cu = code_units.next()
                if isinstance(cu, Data):
                    if cu.is_defined():
                        do_clear = True

                else:
                    return  # don't clear instructions
            if do_clear:
                listing.clear_code_units(addr, max_addr, False)

    def write(self, writer, addrset, monitor):
        monitor.set_message("Writing DATA ...")
        writer.start_element("DATA")

        listing = self.program.get_listing()
        iter = listing.get_defined_data(addrset, True)
        while iter.has_next():
            if monitor.is_cancelled():
                raise CancelledException()

            data = iter.next()

            attrs = XmlAttributes()
            attrs.add_attribute("ADDRESS", str(data.min_address))
            dt = data.data_type
            attrs.add_attribute("DATATYPE", dt.display_name)
            attrs.add_attribute("DATATYPE_NAMESPACE", dt.category_path.path)
            attrs.add_attribute("SIZE", data.length, True)

            writer.start_element("DEFINED_DATA", attrs)

            DisplaySettingsHandler.write_settings(writer, data)

            writer.end_element()

        writer.end_element()
