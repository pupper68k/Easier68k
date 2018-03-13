"""
Op Size Enum
Holds the values for various binary translations of size codes
"""


class MoveSize:
    """
    Represents the "Big S" sizes (dark purple on this chart: http://goldencrystal.free.fr/M68kOpcodes-v2.3.pdf)
    """
    BYTE = 0b01
    WORD = 0b11
    LONG = 0b10

    @staticmethod
    def parse(code: chr) -> int:
        if code == 'B':
            return MoveSize.BYTE
        if code == 'W':
            return MoveSize.WORD
        if code == 'L':
            return MoveSize.LONG
    
    @staticmethod
    def parse_binary(code: int) -> chr:
        if code == MoveSize.BYTE:
            return 'B'
        if code == MoveSize.WORD:
            return 'W'
        if code == MoveSize.LONG:
            return 'L'


class Size:
    """
    Represents the "Small S" sizes (light purple on this chart: http://goldencrystal.free.fr/M68kOpcodes-v2.3.pdf)
    """
    BYTE = 0b00
    WORD = 0b01
    LONG = 0b10

    @staticmethod
    def parse(code: chr) -> int:
        if code == 'B':
            return Size.BYTE
        if code == 'W':
            return Size.WORD
        if code == 'L':
            return Size.LONG

    @staticmethod
    def parse_binary(code: int) -> chr:
        if code == Size.BYTE:
            return 'B'
        if code == Size.WORD:
            return 'W'
        if code == Size.LONG:
            return 'L'


class SingleBitSize:
    """
    Represents the single bit sizes (medium purple on this chart: http://goldencrystal.free.fr/M68kOpcodes-v2.3.pdf)
    """
    WORD = 0b0
    LONG = 0b1
    
    @staticmethod
    def parse(code: chr) -> int:
        if code == 'W':
            return SingleBitSize.WORD
        if code == 'L':
            return SingleBitSize.LONG
    
    @staticmethod
    def parse_binary(code: int) -> chr:
        if code == SingleBitSize.WORD:
            return 'W'
        if code == SingleBitSize.LONG:
            return 'L'
