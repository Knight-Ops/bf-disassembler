from binaryninja import (Architecture, InstructionInfo, InstructionTextToken,
                         RegisterInfo, InstructionTextTokenType, BranchType, ILRegister)
from collections import defaultdict

opcodes = defaultdict(
    lambda: 'hlt',
    {
        0x2b: "Add",
        0x2c: "In",
        0x2d: "Subtract",
        0x2e: "Out",
        0x3c: "Left",
        0x3e: "Right",
        0x5b: "Open",
        0x5d: "Close",
    }
)


class BrainFuck(Architecture):
    name = "Brainfuck"

    address_size = 1
    default_int_size = 1
    max_instr_length = 1

    stack_pointer = 's'

    regs = {
        'ptr': RegisterInfo('ptr', 1),
        's': RegisterInfo('s', 1)
    }

    def parse_instruction(self, data, addr):
        return ord(data), 1

    def get_instruction_info(self, data, addr):
        opcode, length = self.parse_instruction(data, addr)

        info = InstructionInfo()
        info.length = length

        if opcodes[opcode] == 'hlt':
            info.add_branch(BranchType.FunctionReturn)
        elif opcodes[opcode] == 'Close':
            info.add_branch(BranchType.TrueBranch)

        return info

    def get_instruction_text(self, data, addr):
        opcode, length = self.parse_instruction(data, addr)

        tokens = []

        op = opcodes[opcode]

        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.InstructionToken,
                "{}".format(op)
            )
        )

        return tokens, length

    def get_instruction_low_level_il(self, data, addr, il):
        opcode, length = self.parse_instruction(data, addr)

        op = opcodes[opcode]

        if op == "Right":
            il.append(
                il.add(1, il.reg(1, 'ptr'), il.const(1, 1))
            )
        elif op == "Left":
            il.append(
                il.sub(1, il.reg(1, 'ptr'), il.const(1, 1))
            )
        elif op == "Add":
            il.append(
                il.add(1, il.load(1, il.reg(1, 'ptr')), il.const(1, 1))
            )
        elif op == "Subtract":
            il.append(
                il.sub(1, il.load(1, il.reg(1, 'ptr')), il.const(1, 1))
            )
        elif op == "In":
            il.append(
                il.unimplemented()
            )
        elif op == "Out":
            il.append(
                il.unimplemented()
            )
        elif op == "Open":
            il.append(
                il.nop()
            )
        elif op == "Close":
            il.append(
                il.nop()
            )

        return length


BrainFuck.register()
