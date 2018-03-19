from ...core.enum.ea_mode import EAMode
from ...core.enum.op_size import MoveSize, OpSize
from ...core.enum import ea_mode_bin
from ...core.enum.ea_mode_bin import parse_ea_from_binary
from ...simulator.m68k import M68K
from ...core.opcodes.opcode import Opcode
from ...core.util.split_bits import split_bits
from ...core.util import opcode_util
from ..util.parsing import parse_assembly_parameter, parse_literal, from_str_util
from ..models.assembly_parameter import AssemblyParameter
import binascii


class Bra(Opcode):  # Forward declaration
    pass


class Bra(Opcode):
    # IMPORTANT NOTE: this is a tricky command to implement due to how our system is set up.
    # Luckily, IMMEDIATES are not legal arguments: this means we have a way to send extra "unconventional" data from the
    # assembler (such as memory location of the operation) and have it earmarked as such. This means that we're going to
    # add on an extra argument in the assembler as an immediate, the current memory address, which will then be
    # irrelevant once parsed.
    def __init__(self, offset: int, size: OpSize = OpSize.WORD):
        assert isinstance(offset, int)
        self.offset = offset
        self.size = size

    def assemble(self) -> bytearray:
        """
        NOTE: For some reason this isn't matching up with the results from EASy68k: more research
        needs to be done. For now, this should function properly with our own simulator?

        Assembles this opcode into hex to be inserted into memory
        :return: The hex version of this opcode
        """
        tr = '01100000'  # The base opcode
        if self.size is OpSize.BYTE:
            xormask = 0xFF
            onescomp = self.offset ^ xormask
            twoscomp = onescomp + 0b1
            tr += '{:08b}'.format(twoscomp)
        elif self.size is OpSize.WORD:
            tr += '00000000'
            xormask = 0xFFFF
            onescomp = self.offset ^ xormask
            twoscomp = onescomp + 0b1
            tr += '{:016b}'.format(twoscomp)
        else:  # OpSize.LONG
            tr += '11111111'
            xormask = 0xFFFFFFFF
            onescomp = self.offset ^ xormask
            twoscomp = onescomp + 0b1
            tr += '{:032b}'.format(twoscomp)

        return bytearray.fromhex(hex(int(tr, 2))[2:])  # Convert to a bytearray

    def execute(self, simulator: M68K):
        """
        Executes this command in a simulator
        :param simulator: The simulator to execute the command on
        :return: Nothing
        """
        if self.size is OpSize.BYTE:
            length = 2  # Just the opcode word
        if self.size is OpSize.WORD:
            length = 4  # The opcode word + the word afterwards
        if self.size is OpSize.LONG:
            length = 6  # The opcode word + the 2 words afterwards

        # Move by the offset + the length of this instruction
        simulator.increment_program_counter(self.offset + length)

    def __str__(self):
        return 'Branch command: offset {}, size {}'.format(self.offset, self.size)

    @classmethod
    def command_matches(cls, command: str) -> bool:
        """
        Checks whether a command string is an instance of this command type
        :param command: The command string to check (e.g. 'MOVE.B', 'LEA', etc.)
        :return: Whether the string is an instance of this command type
        """
        return opcode_util.command_matches(command, 'BRA')

    @classmethod
    def get_word_length(cls, command: str, parameters: str) -> int:
        """
        >>> Bra.get_word_length('BRA', '($1081).L, #$1000')
        1

        >>> Bra.get_word_length('BRA', '($1082).L, #$1000')
        2

        >>> Bra.get_word_length('BRA', '$100')
        2

        >>> Bra.get_word_length('BRA', '$1000')
        2

        Gets what the end length of this command will be in memory
        :param command: The text of the command itself (e.g. "LEA", "MOVE.B", etc.)
        :param parameters: The parameters after the command
        :return: The length of the bytes in memory in words, as well as a list of warnings or errors encountered
        """
        split = parameters.split(',')
        param = parse_assembly_parameter(split[0])
        if param is None:
            # Parse this as a literal
            offset = parse_literal(split[0].strip())
        else:
            # Parse this as an EA mode
            # This is where we use that assembler-added memory address immediate
            current_address = parse_assembly_parameter(split[1].strip())
            offset = param.data - current_address.data - 2

        # Two's comp-ify the number
        xormask = int('1' * offset.bit_length(), 2)
        onescomp = offset ^ xormask
        twoscomp = onescomp + 1
        if twoscomp.bit_length() > 15:  # Uses all 48 bits
            return 3
        elif twoscomp.bit_length() > 7:  # Uses 32 bits
            return 2
        else:  # Uses just 1 word/16 bits
            return 1

    @classmethod
    def is_valid(cls, command: str, parameters: str) -> (bool, list):
        """
        Tests whether the given command is valid

        >>> Bra.is_valid('BRA', '$AB, #$400')[0]
        True

        >>> Bra.is_valid('BRA', '($ABCD).W, #$400')[0]
        True

        >>> Bra.is_valid('BRA', '($ABCD).L')[0]
        False

        >>> Bra.is_valid('BRA.W', '$AB, #$400')[0]
        False

        >>> Bra.is_valid('BRA.', '$AB, #$400')[0]
        False

        >>> Bra.is_valid('BR', '$AB, #$400')[0]
        False

        >>> Bra.is_valid('BRA', '$AB')[0]
        True

        >>> Bra.is_valid('BRA', 'A0')[0]
        False

        TODO: offset range checking (make sure it's a valid location)

        :param command: The command itself (e.g. 'MOVE.B', 'LEA', etc.)
        :param parameters: The parameters after the command (such as the source and destination of a move)
        :return: Whether the given command is valid and a list of issues/warnings encountered
        """
        issues = []
        try:
            assert command.upper() == 'BRA', 'Command does not match'

            params = parameters.split(',')
            assert len(params) >= 1
            offset_param = parse_assembly_parameter(params[0].strip())
            if offset_param is None:
                parse_literal(params[0])  # Just try it to make sure it parses right
            else:
                assert offset_param.mode in [EAMode.AWA, EAMode.ALA], 'Invalid addressing mode'
                assert len(params) == 2, 'Missing assembler-generated immediate specifying memory location'
                current_memory = parse_assembly_parameter(params[1].strip())
                assert current_memory and current_memory.mode is EAMode.IMM, 'Error parsing assembler-generated immediate'

        except AssertionError as e:
            issues.append((e.args[0], 'ERROR'))
            return False, issues

        return True, issues

    @classmethod
    def disassemble_instruction(cls, data: bytearray) -> Opcode:
        """
        This has a non-bra opcode
        >>> Bra.disassemble_instruction(bytearray.fromhex('5E01'))

        Parses some raw data into an instance of the opcode class
        :param data: The data used to convert into an opcode instance
        :return: The constructed instance or none if there was an error and
            the amount of data in words that was used (e.g. extra for immediate
            data) or 0 for not a match
        """
        assert len(data) >= 2, 'opcode size is at least one word'

        first_word = int.from_bytes(data[0:2], 'big')
        opcode_bin, displacement = split_bits(first_word, [8, 8])

        if opcode_bin != 0b01100000:
            return None

        words_used = 1

        if displacement == 0x00:
            offset = int.from_bytes(data[2:4], 'big')
            size = OpSize.WORD
            words_used += 1
        elif displacement == 0xFF:
            offset = int.from_bytes(data[2:6], 'big')
            size = OpSize.LONG
            words_used += 2
        else:
            offset = displacement
            size = OpSize.BYTE

        return cls(offset, size)

    @classmethod
    def from_str(cls, command: str, parameters: str):
        """
        >>> str(Bra.from_str('BRA', '($1081).L, #$1000'))
        'Branch command: offset 127, size OpSize.BYTE'

        >>> str(Bra.from_str('BRA', '($1082).L, #$1000'))
        'Branch command: offset 128, size OpSize.WORD'

        :param command: The command itself (e.g. 'MOVE.B', 'LEA', etc.)
        :param parameters: The parameters after the command (such as the source and destination of a move)
        :return: The parsed command
        """
        params = parameters.split(',')
        offset_param = parse_assembly_parameter(params[0].strip())
        if offset_param is None:
            offset = parse_literal(params[0].strip())
        else:
            current_memory = parse_assembly_parameter(params[1].strip())
            offset = offset_param.data - current_memory.data - 2

        # Two's comp-ify the number
        xormask = int('1' * offset.bit_length(), 2)
        onescomp = offset ^ xormask
        twoscomp = onescomp + 1
        if twoscomp.bit_length() > 15:  # Uses all 32 bits
            return cls(offset, OpSize.LONG)
        elif twoscomp.bit_length() > 7:  # Uses 16 bits
            return cls(offset, OpSize.WORD)
        else:  # Uses just 8 bits
            return cls(offset, OpSize.BYTE)
