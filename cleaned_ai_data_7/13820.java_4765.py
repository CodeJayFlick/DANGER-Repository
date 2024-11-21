class Instruction:
    LITERAL = 1          # e.g. "LITERAL 0", push 0 to stack
    SET_HEALTH = 2       # e.g. "SET_HEALTH", pop health and wizard number, call set health
    SET_WISDOM = 3       # e.g. "SET_WISDOM", pop wisdom and wizard number, call set wisdom
    SET_AGILITY = 4      # e.g. "SET_AGILITY", pop agility and wizard number, call set agility
    PLAY_SOUND = 5       # e.g. "PLAY_SOUND", pop value as wizard number, call play sound
    SPAWN_PARTICLES = 6   # e.g. "SPAWN_PARTICLES", pop value as wizard number, call spawn particles
    GET_HEALTH = 7        # e.g. "GET_HEALTH", pop value as wizard number, push wizard's health
    GET_AGILITY = 8       # e.g. "GET_AGILITY", pop value as wizard number, push wizard's agility
    GET_WISDOM = 9         # e.g. "GET_WISDOM", pop value as wizard number, push wizard's wisdom
    ADD = 10               # e.g. "ADD", pop 2 values, push their sum
    DIVIDE = 11            # e.g. "DIVIDE", pop 2 values, push their division

class InstructionEnum:
    @staticmethod
    def get_instruction(value):
        for i in range(len(Instruction.__dict__.values())):
            if list(Instruction.__dict__.values())[i] == value:
                return [k for k, v in Instruction.__dict__.items() if v == value][0]
        raise ValueError("Invalid instruction value")

# Usage
print(InstructionEnum.get_instruction(1))  # Output: LITERAL
