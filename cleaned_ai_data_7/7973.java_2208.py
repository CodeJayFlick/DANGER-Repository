class PdbUtil:
    @staticmethod
    def reladdr(program: 'Program', relative_offset: int) -> 'Address':
        return program.get_image_base().add(relative_offset & 0xFFFFFFFF)

    @staticmethod
    def append_comment(program: 'Program', address: 'Address', text: str, comment_type: int):
        if (comment := program.get_listing().get_comment(comment_type, address)) is not None:
            if comment.contains(text):
                return
            text = f"{comment}\n{text}"
        SetCommentCmd.create_comment(program, address, text, comment_type)

    @staticmethod
    def is_function(program: 'Program', symbol: str, addr: 'Address', length: int) -> bool:
        atpos = symbol.rfind('@')
        if atpos > 0:
            s = symbol[atpos + 1:]
            try:
                int(s)
            except ValueError:
                return False
            dis = PseudoDisassembler(program)
            tmp = addr
            while (tmp - addr) < length:
                try:
                    instr = dis.disassemble(tmp)
                    tmp += instr.get_length()
                except Exception:
                    return False
            return True
        return False

    @staticmethod
    def clear_components(composite: 'Composite'):
        if isinstance(composite, Structure):
            composite.delete_all()
        else:
            while composite.num_components > 0:
                composite.delete(0)

    @staticmethod
    def get_pass(pass_num: int) -> str:
        if pass_num > 20:
            pass_num %= 10
        match pass_num:
            case 1: return f"{pass_num}st pass"
            case 2: return f"{pass_num}nd pass"
            case 3: return f"{pass_num}rd pass"
            case _: return f"{pass_num}th pass"


class Program:
    def get_image_base(self) -> 'Address':
        # implementation
        pass

    def get_listing(self):
        # implementation
        pass


class Address:
    def add(self, offset: int) -> 'Address':
        # implementation
        pass


class Composite:
    @property
    def num_components(self) -> int:
        # implementation
        pass

    def delete_all(self):
        # implementation
        pass

    def delete(self, index: int):
        # implementation
        pass


class Structure(Composite):
    def delete_all(self):
        super().delete_all()


class PseudoDisassembler:
    def __init__(self, program: 'Program'):
        self.program = program

    @staticmethod
    def disassemble(address: 'Address') -> 'PseudoInstruction':
        # implementation
        pass


class SetCommentCmd:
    @staticmethod
    def create_comment(program: 'Program', address: 'Address', text: str, comment_type: int):
        # implementation
        pass


class PseudoInstruction:
    def get_length(self) -> int:
        # implementation
        pass
