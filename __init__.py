from binaryninja import (Architecture, InstructionInfo, InstructionTextToken,
                         RegisterInfo, InstructionTextTokenType, BranchType,
                         ILRegister, BinaryReader, BinaryView, BinaryViewType,
                         CallingConvention, Platform, SegmentFlag, log_error,
                         SectionSemantics)
from collections import defaultdict

opcodes = defaultdict(
    lambda: '',
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


class BFView(BinaryView):
    name = "Brainf***"
    long_name = "Brainf*** View"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def init(self):
        try:
            self.arch = Architecture['Brainfuck']
            self.add_auto_segment(0x10000, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable |
                                  SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode)
            self.add_user_segment(0, 30000, len(self.parent_view), len(self.parent_view)+30000, SegmentFlag.SegmentReadable |
                                  SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData)
            self.write(0, '\x00'*30000)
            # self.platform = Platform['Brainfuck']

            self.add_auto_section(
                '.bfvm', 0, 30000, SectionSemantics.ReadWriteDataSectionSemantics)
            self.add_auto_section(
                '.text', 0x10000, len(self.parent_view), SectionSemantics.ReadOnlyCodeSectionSemantics)

            # self.add_entry_point(0x10000)

        #     self.add_analysis_option('linearsweep')
            self.parent_view.update_analysis()
            self.update_analysis()
        except:
            log_error("Error during initialization")
            return False

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x10000


class Brainfuck(Architecture):
    name = "Brainfuck"

    address_size = 1
    default_int_size = 1
    max_instr_length = 1

    stack_pointer = 's'

    regs = {
        'tmp': RegisterInfo('tmp', 1),
        'ptr': RegisterInfo('ptr', 4),
        's': RegisterInfo('s', 1)
    }

    def parse_instruction(self, data, addr):
        try:
            ret_data = ord(data)
        except:
            ret_data = data
        return ret_data, 1

    def get_instruction_info(self, data, addr):
        opcode, length = self.parse_instruction(data, addr)

        info = InstructionInfo()
        info.length = length

        if opcodes[opcode] == 'Close':
            info.add_branch(BranchType.UnresolvedBranch)
            info.add_branch(BranchType.FalseBranch, addr + 1)
        elif opcodes[opcode] == 'Open':
            info.add_branch(BranchType.TrueBranch, addr + 1)
            info.add_branch(BranchType.UnresolvedBranch)

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

        if addr == 0x10000:
            il.append(
                il.set_reg(4, 'ptr', il.const(1, 0))
            )

        if op == "Right":
            il.append(
                il.set_reg(4, 'ptr', il.add(
                    4, il.reg(4, 'ptr'), il.const(1, 1)), None)
            )
        elif op == "Left":
            il.append(
                il.set_reg(4, 'ptr', il.sub(
                    4, il.reg(4, 'ptr'), il.const(1, 1)), None)
            )
        elif op == "Add":
            il.append(
                il.store(1, il.reg(4, 'ptr'), il.add(
                    1, il.load(1, il.reg(4, 'ptr')), il.const(1, 1)), None)
            )
        elif op == "Subtract":
            il.append(
                il.store(1, il.reg(4, 'ptr'), il.sub(
                    1, il.load(1, il.reg(4, 'ptr')), il.const(1, 1)), None)
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
            true_label = il.get_label_for_address(
                Architecture['Brainfuck'], addr + 1)

            br = BinaryReader(il._source_function._view)
            br.seek(addr+1)
            # print("Found Open at : ", br.offset-1)
            counter = 1
            while counter != 0:
                instr = opcodes[br.read8()]
                if instr == "Open":
                    counter += 1
                elif instr == "Close":
                    counter -= 1
                    if counter == 0:
                        false_label = il.get_label_for_address(
                            Architecture['Brainfuck'], br.offset)
                        # print("Found loop close at offset : ", br.offset-1)
                        break
                elif br.offset == il._source_function._view.end:
                    print("Unfinished loop! This should never happen!")
                    return

            il.append(
                il.if_expr(il.compare_not_equal(1, il.load(
                    1, il.reg(4, 'ptr')), il.const(1, 0)), true_label, false_label)
            )
        elif op == "Close":
            false_label = il.get_label_for_address(
                Architecture['Brainfuck'], addr + 1)

            br = BinaryReader(il._source_function._view)
            br.seek(addr)
            # print("Found Close at : ", br.offset)
            counter = 1
            while counter != 0:
                br.seek_relative(-2)
                instr = opcodes[br.read8()]
                if instr == "Close":
                    counter += 1
                elif instr == "Open":
                    counter -= 1
                    if counter == 0:
                        true_label = il.get_label_for_address(
                            Architecture['Brainfuck'], br.offset)
                        # print("Found loop Open at offset : ", br.offset-1)
                        break
                elif br.offset == il._source_function._view.end:
                    print("Unfinished loop! This should never happen!")
                    return

            il.append(
                il.if_expr(il.compare_not_equal(1, il.load(
                    1, il.reg(4, 'ptr')), il.const(1, 0)), true_label, false_label)
            )
        else:
            il.append(
                il.nop()
            )

        return length


Brainfuck.register()
BFView.register()
