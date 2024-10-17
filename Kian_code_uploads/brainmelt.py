
class Interpreter:
    pointer = 1  # This is the current focus
    tape = [0] * 3  # This is the "infinite" tape
    command_string = []  # This is the list of instructions
    input_string = []  # This is a string of input to read
    current_command = 0
    current_input = 0

    def __init__(self, command_string, input_string):
        # Save our input file into our string
        self.command_string = list(command_string)
        self.input_string = list(input_string)

    def execute(self):
        num_open = self.command_string.count('[')
        num_close = self.command_string.count(']')
        length = len(self.command_string)

        if num_open == num_close:
            while self.current_command < length:
                # print(f'Current command pointer: {self.current_command}')
                # print(f'Current command: {self.command_string[self.current_command]}')
                # time.sleep(1)
                if self.command_string[self.current_command] == '<':
                    self.__left__()
                elif self.command_string[self.current_command] == '>':
                    self.__right__()
                elif self.command_string[self.current_command] == '.':
                    self.__print__()
                elif self.command_string[self.current_command] == '+':
                    self.__increment__()
                elif self.command_string[self.current_command] == '-':
                    self.__decrement__()
                elif self.command_string[self.current_command] == '[':
                    self.__open_bracket__()
                elif self.command_string[self.current_command] == ']':
                    self.__close_bracket__()
                elif self.command_string[self.current_command] == ',':
                    self.__comma__()
                self.current_command += 1
        else:
            print("Error! Unmatched bracket found in program.")

    def __left__(self):
        if self.pointer == 0:  # We need to shift the elements of the tape right
            self.tape.append(0)
            length = len(self.tape) - 1
            for i in range(length, 1, -1):
                self.tape[i] = self.tape[i - 1]
            self.tape[0] = 0
        else:
            self.pointer -= 1

    def __right__(self):
        if self.pointer >= len(self.tape) - 1:
            self.tape.append(0)
            self.pointer += 1
        else:
            self.pointer += 1

    def __print__(self):
        print(chr(self.tape[self.pointer]), end='')

    def __increment__(self):
        self.tape[self.pointer] = self.tape[self.pointer] + 1

    def __decrement__(self):
        if self.tape[self.pointer] > 0:
            self.tape[self.pointer] = self.tape[self.pointer] - 1

    def __open_bracket__(self):
        if self.tape[self.pointer] <= 0:
            num_open = -1
            while self.command_string[self.current_command] != ']' or num_open > 0:
                if self.command_string[self.current_command] == '[':
                    num_open += 1
                elif self.command_string[self.current_command] == ']':
                    num_open -= 1
                self.current_command += 1

    def __close_bracket__(self):
        if self.tape[self.pointer] > 0:
            num_close = -1
            while self.command_string[self.current_command] != '[' or num_close > 0:
                if self.command_string[self.current_command] == ']':
                    num_close += 1
                elif self.command_string[self.current_command] == '[':
                    num_close -= 1
                self.current_command -= 1

    def __comma__(self):
        self.tape[self.pointer] = ord(self.input_string[self.current_input])
        self.current_input += 1


# Example usage, prints 'Hello World!'
hello_command = '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.'
reader = Interpreter(hello_command, '')
reader.execute()
