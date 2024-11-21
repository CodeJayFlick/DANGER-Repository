class InjectInvokeInterface:
    def __init__(self, source_name: str, language: object, uniq_base: int):
        pass  # super().__init__(source_name, language, uniq_base)

    def get_pcode(self, program: object, con: object) -> list:
        constant_pool = []  # equivalent to AbstractConstantPoolInfoJava[]
        constant_pool_index = int(con.inputlist[0].get_offset())  # equivalent to (int) con. inputlist.get(0).getOffset()
        
        p_code = PcodeOpEmitter(language, con.base_addr, uniq_base)
        invoke_methods = InvokeMethods()  # assuming this is a class with getPcodeForInvoke method
        p_code_ops = invoke_methods.get_pcode_for_invoke(p_code, constant_pool_index, constant_pool, JavaInvocationType.INVOKE_INTERFACE)  # equivalent to InvokeMethods.getPcodeForInvoke
        
        return [p_code_op for p_code_op in p_code_ops]  # assuming getPcodeOps returns a list of PcodeOp
