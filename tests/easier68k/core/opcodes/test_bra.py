"""
Test methods for the move command
"""

from easier68k.simulator.m68k import M68K
from easier68k.core.opcodes.branches import Bra
from easier68k.core.enum.ea_mode import EAMode
from easier68k.core.models.assembly_parameter import AssemblyParameter
from easier68k.core.enum.register import Register
from easier68k.core.enum.op_size import OpSize

def test_bra():
    """
    Test to see that move works as intended
    :return:
    """

    # make a simulator class
    a = M68K()

    a.set_program_counter_value(0x1000)

    # test immediate -> data register

    # make a testing bra command
    bra = Bra(4, OpSize.BYTE)
    bra.execute(a)

    assert a.get_program_counter_value() == 0x1006

    # make a testing bra command going backwards
    bra = Bra(-4, OpSize.BYTE)
    bra.execute(a)

    assert a.get_program_counter_value() == 0x1004
