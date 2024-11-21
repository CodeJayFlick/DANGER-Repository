class ClangVariableToken:
    def __init__(self):
        self.varnode = None
        self.op = None

    @property
    def varnode(self):
        return self._varnode

    @varnode.setter
    def varnode(self, value):
        self._varnode = value

    @property
    def op(self):
        return self._op

    @op.setter
    def op(self, value):
        self._op = value

    def get_varnode(self):
        return self.varnode

    def get_pcode_op(self):
        return self.op

    def is_variable_ref(self):
        return True

    def get_min_address(self):
        if not self.op:
            return None
        return self.op.get_seqnum().get_target().get_physical_address()

    def get_max_address(self):
        if not self.op:
            return None
        return self.op.get_seqnum().get_target().get_physical_address()

    def get_high_variable(self):
        inst = self.varnode
        if inst is not None:
            hvar = inst.get_high()
            if hvar and hvar.get_representative() is None:
                instances = [inst]
                hvar.attach_instances(instances, inst)
            return inst.get_high()
        return super().get_high_variable()

    def restore_from_xml(self, el, end, pfactory):
        self.restore_from_xml_helper(el, end, pfactory)

    @staticmethod
    def restore_from_xml_helper(el, end, pfactory):
        if 'varnode_ref' in el.attrib:
            ref_id = int(el.get('varnode_ref'))
            var_node = pfactory.get_ref(ref_id)
            return var_node

        if 'op_ref' in el.attrib:
            ref_id = int(el.get('op_ref'))
            op = pfactory.get_op_ref(ref_id)
            return op
