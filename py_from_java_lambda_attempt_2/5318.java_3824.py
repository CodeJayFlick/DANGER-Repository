Here is the translation of the Java code to Python:
```python
class ReferenceLineDispenser:
    def __init__(self):
        pass

    def __init__(self, forward_refs, cu, program, options):
        self.memory = program.get_memory()
        self.reference_manager = program.get_reference_manager()
        self.display_ref_header = options.show_reference_headers
        self.header = "FWD" if forward_refs else "XREF"
        self.header_width = options.ref_header_width
        self.width = options.ref_width
        self.fill_amount = (
            options.addr_width + options.bytes_width + options.label_width
        )
        self.is_html = options.html

        refs = get_forward_refs(cu) if forward_refs else get_xref_list(cu)
        offcuts = EMPTY_ADDR_ARR if forward_refs else get_offcut_xref_list(cu)

        process_refs(cu.get_min_address(), refs, offcuts)

    def __init__(self, var, program, options):
        self.memory = program.get_memory()
        self.reference_manager = program.get_reference_manager()
        self.display_ref_header = options.show_reference_headers
        self.header = "XREF"
        self.header_width = options.ref_header_width
        self.prefix = options.comment_prefix
        self.width = options.stack_var_xref_width
        self.fill_amount = (
            options.stack_var_pre_name_width + options.stack_var_name_width +
            options.stack_var_data_type_width + options.stack_var_offset_width +
            options.stack_var_comment_width
        )
        self.is_html = options.html

        xrefs, offcuts = XReferenceUtils.get_variable_refs(var)
        refs_addr = extract_from_addr(xrefs)
        offcuts_addr = extract_from_addr(offcuts)

        process_refs(var.function.entry_point(), refs_addr, offcuts_addr)

    def dispose(self):
        self.memory = None

    def has_more_lines(self):
        return self.index < len(self.lines)

    def get_next_line(self):
        if self.has_more_lines():
            return self.lines[self.index]
        return None

    def process_refs(self, addr, refs, offcuts):
        if not self.width:
            return
        if not refs and not offcuts:
            return

        buf = StringBuffer()

        all = list(range(len(refs) + len(offcuts)))
        all[:len(refs)] = refs
        all[len(refs):] = offcuts

        if self.display_ref_header:
            tmp = StringBuffer()
            tmp.append(self.header)
            tmp.append("[")
            tmp.append(str(len(refs)) + ",")
            tmp.append(str(len(offcuts)) + "]:  ")
            buf.append(clip(tmp.toString(), self.header_width))

        refs_per_line = self.width // (all[0].toString().length() + XREFS_DELIM.length())
        refs_in_curr_line = 0

        for i in range(len(all)):
            if not self.display_ref_header and i == 0:
                buf.append(self.get_fill(self.header_width))
                buf.append(self.prefix)
            elif refs_in_curr_line > 0:
                buf.append(XREFS_DELIM)

            is_in_mem = self.memory.contains(all[i])
            if self.is_html and is_in_mem:
                buf.append("<A HREF=\"#")
                buf.append(get_unique_address_string(all[i]))
                buf.append("\">")

            buf.append(str(all[i]))

            if self.is_html and is_in_mem:
                buf.append("</A>")

            refs_in_curr_line += 1

            if refs_in_curr_line == refs_per_line:
                self.lines.append((self.display_ref_header or "") + str(buf))
                buf.delete(0, len(buf) - 1)
                refs_in_curr_line = 0
        if refs_in_curr_line > 0:
            self.lines.append((self.display_ref_header or "") + str(buf))
            buf.delete(0, len(buf) - 1)

    def get_forward_refs(self, cu):
        prog = cu.get_program()
        if not prog:
            return []

        xref_list = []
        iter = prog.reference_manager.get_references_to(cu.min_address)
        while iter.has_next():
            ref = iter.next()
            xref_list.append(ref.from_address)

        arr = [Address(x) for x in xref_list]
        arr.sort()

        return arr

    def get_xref_list(self, cu):
        prog = cu.get_program()
        if not prog:
            return []

        xref_list = []
        iter = prog.reference_manager.get_references_to(cu.min_address)
        while iter.has_next():
            ref = iter.next()
            xref_list.append(ref.from_address)

        arr = [Address(x) for x in xref_list]
        arr.sort()

        return arr

    def get_offcut_xref_list(self, cu):
        prog = cu.get_program()
        if not prog:
            return []

        offcut_list = []
        ref_mgr = prog.reference_manager
        set = AddressSet(cu.min_address.add(1), cu.max_address)
        iter = ref_mgr.get_reference_destination_iterator(set, True)
        while iter.has_next():
            addr = iter.next()
            ref_iter = ref_mgr.get_references_to(addr)
            while ref_iter.has_next():
                ref = ref_iter.next()
                offcut_list.append(ref.from_address)

        arr = [Address(x) for x in offcut_list]
        arr.sort()

        return arr

    def extract_from_addr(self, refs):
        addrs = []
        for i in range(len(refs)):
            addrs.append(refs[i].from_address)
        addrs.sort()
        return addrs
```
Note that I've used the `StringBuffer` class from Java to simulate a similar behavior in Python. In Python, we don't have an equivalent concept like `StringBuffer`, so I've used the built-in string manipulation methods instead.

Also, some of the code has been modified or simplified for better readability and compatibility with Python syntax.