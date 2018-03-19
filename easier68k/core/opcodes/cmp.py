from ...core.enum.ea_mode import EAMode
from ...core.models.assembly_parameter import AssemblyParameter
from ...core.enum import ea_mode_bin
from ...core.enum.ea_mode_bin import parse_ea_from_binary
from ...simulator.m68k import M68K
from ...core.enum.condition_status_code import ConditionStatusCode
from ...core.util.split_bits import split_bits
from ...core.opcodes.opcode import Opcode
from ...core.util import opcode_util
from ...core.enum.op_size import OpSize
from ..util.parsing import parse_assembly_parameter


class Cmp(Opcode):  # Forward declaration
    pass


class Cmp(Opcode):
    valid_sizes = [OpSize.BYTE, OpSize.WORD, OpSize.LONG]

    def __init__(self, params: list, size: OpSize=OpSize.WORD):
        assert len(params) == 2
        assert isinstance(params[0], AssemblyParameter)
        assert isinstance(params[1], AssemblyParameter)

        # Any EA mode is valid...
        self.ea = params[0]

        # ...while the register param has to be DRD
        assert params[1].mode == EAMode.DRD
        self.register = params[1]

        assert size in Cmp.valid_sizes
        self.size = size

    def assemble(self) -> bytearray:
        """
        Assembles this opcode into hex to be inserted into memory
        :return: The hex version of this opcode
        """
        tr = '1011'
        tr += '{0:03b}'.format(self.register.data)
        if self.size == OpSize.BYTE:
            tr += '000'
        elif self.size == OpSize.WORD:
            tr += '001'
        elif self.size == OpSize.LONG:
            tr += '010'

        tr += ea_mode_bin.parse_from_ea_mode_modefirst(self.ea)

        return bytearray.fromhex(hex(int(tr, 2))[2:])

    def execute(self, simulator: M68K):
        """
        Executes this command in a simulator
        :param simulator: The simulator to execute the command on
        :return: Nothing
        """
        val_len = self.size.get_number_of_bytes()
        ea_val = self.ea.get_value(simulator, val_len)
        reg_val = self.register.get_value(simulator, val_len)
        result = reg_val - ea_val

        simulator.set_condition_status_code(ConditionStatusCode.N, result < 0)
        simulator.set_condition_status_code(ConditionStatusCode.Z, result == 0)

        simulator.increment_program_counter(2)

    def __str__(self):
        return 'CMP command: ea {}, register {}'.format(self.ea, self.register)

    @classmethod
    def command_matches(cls, command: str) -> bool:
        """
        Checks whether a command string is an instance of this command type
        :param command: The command string to check (e.g. 'MOVE.B', 'LEA', etc.)
        :return: Whether the string is an instance of this command type
        """
        return opcode_util.command_matches(command, 'CMP')

    @classmethod
    def get_word_length(cls, command: str, parameters: str) -> int:
        """
        >>> Cmp.get_word_length('CMP.W', '(A0), D1')
        1

        >>> Cmp.get_word_length('CMP.W', '#$0, D3')
        2

        >>> Cmp.get_word_length('CMP.L', '#$ABCDE, D0')
        3

        >>> Cmp.get_word_length('CMP.L', '#$A, D3')
        3

        >>> Cmp.get_word_length('CMP.L', '($AAAA).L, D6')
        3

        >>> Cmp.get_word_length('CMP.W', '($AAAA).W, D5')
        2

        Gets what the end length of this command will be in memory
        :param command: The text of the command itself (e.g. "LEA", "MOVE.B", etc.)
        :param parameters: The parameters after the command
        :return: The length of the bytes in memory in words, as well as a list of warnings or errors encountered
        """
        parts = command.split('.')  # Split the command by period to get the size of the command
        if len(parts) == 1:  # Use the default size
            size = OpSize.WORD
        else:
            size = OpSize.parse(parts[1])

        # Split the parameters into EA modes
        params = parameters.split(',')

        if len(params) != 2:  # We need exactly 2 parameters
            return 0

        ea = parse_assembly_parameter(params[0].strip())  # Parse the source and make sure it parsed right

        length = 1  # Always 1 word not counting additions to end

        if ea.mode == EAMode.IMM:  # If we're moving an immediate we have to append the value afterwards
            if size == OpSize.LONG:
                length += 2
            else:
                length += 1

        if ea.mode == EAMode.AWA:  # Appends a word
            length += 1

        if ea.mode == EAMode.ALA:  # Appends a long, so 2 words
            length += 2

        # No register checks since it'll always be DRD

        return length

    @classmethod
    def is_valid(cls, command: str, parameters: str) -> (bool, list):
        """
        Tests whether the given command is valid

        >>> Cmp.is_valid('CMP.B', 'D0, D1')[0]
        True

        >>> Cmp.is_valid('CMP.W', 'A3, D7')[0]
        True

        >>> Cmp.is_valid('CMP.L', '#$ABCD, D3')[0]
        True

        >>> Cmp.is_valid('CMP.W', '($0A0B).L, D5')[0]
        True

        >>> Cmp.is_valid('COMP.W', '#AB, D3')[0]
        False

        >>> Cmp.is_valid('CMP.G', 'D0, D7')[0]
        False

        :param command: The command itself (e.g. 'MOVE.B', 'LEA', etc.)
        :param parameters: The parameters after the command (such as the source and destination of a move)
        :return: Whether the given command is valid and a list of issues/warnings encountered
        """
        return opcode_util.n_param_is_valid(command, parameters, "CMP", 2, Cmp.valid_sizes, OpSize.WORD,
                                            param_invalid_modes=[[], [mode for mode in EAMode if mode is not EAMode.DRD]][:2])  # Select all but DRD

    @classmethod
    def disassemble_instruction(cls, data: bytearray) -> Opcode:
        """
        This has a non-CMP opcode
        >>> Cmp.disassemble_instruction(bytearray.fromhex('D280'))


        CMP.B #0, D1
        >>> op = Cmp.disassemble_instruction(bytearray.fromhex('B23C0000'))

        >>> str(op.ea)
        'EA Mode: EAMode.IMM, Data: 0'

        >>> str(op.register)
        'EA Mode: EAMode.DRD, Data: 1'

        CMP.W D3, D0
        >>> op = Cmp.disassemble_instruction(bytearray.fromhex('B043'))

        >>> str(op.ea)
        'EA Mode: EAMode.DRD, Data: 3'

        >>> str(op.register)
        'EA Mode: EAMode.DRD, Data: 0'

        CMP.L ($0A0B0C0D).L, D7
        >>> op = Cmp.disassemble_instruction(bytearray.fromhex('BE79000A0B0C'))

        >>> str(op.ea)
        'EA Mode: EAMode.ALA, Data: 658188'

        >>> str(op.register)
        'EA Mode: EAMode.DRD, Data: 7'

        Parses some raw data into an instance of the opcode class
        :param data: The data used to convert into an opcode instance
        :return: The constructed instance or none if there was an error and
            the amount of data in words that was used (e.g. extra for immediate
            data) or 0 for not a match
        """
        assert len(data) >= 2, 'Opcode size is at least one word'

        first_word = int.from_bytes(data[0:2], 'big')
        [opcode_bin,
         register_bin,
         opmode_bin,
         ea_mode_bin,
         ea_reg_bin] = split_bits(first_word, [4, 3, 3, 3, 3])

        if opcode_bin != 0b1011:
            return None

        if opmode_bin == 0b0:
            size = OpSize.BYTE
        elif opmode_bin == 0b1:
            size = OpSize.WORD
        elif opmode_bin == 0b10:
            size = OpSize.LONG
        else:
            return None

        words_used = 1

        register = AssemblyParameter(EAMode.DRD, register_bin)

        ea = parse_ea_from_binary(ea_mode_bin, ea_reg_bin, size, data[words_used * 2:])

        return cls([ea[0], register], size)

    @classmethod
    def from_str(cls, command: str, parameters: str):
        """
        Parses a CMP command from text.

        >>> str(Cmp.from_str('CMP.B', '-(A0), D3'))
        'CMP command: ea EA Mode: EAMode.ARIPD, Data: 0, register EA Mode: EAMode.DRD, Data: 3'

        >>> str(Cmp.from_str('CMP.W', '($0A0B).W, D5'))
        'CMP command: ea EA Mode: EAMode.AWA, Data: 2571, register EA Mode: EAMode.DRD, Data: 5'

        :param command: The command itself (e.g. 'MOVE.B', 'LEA', etc.)
        :param parameters: The parameters after the command (such as the source and destination of a move)
        :return: The parsed command
        """
        return opcode_util.n_param_from_str(command, parameters, Cmp, 2, OpSize.WORD)
