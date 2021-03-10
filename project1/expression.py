"""
Tools for building arithmetic expressions to execute with SMC.

Example expression:
>>> alice_secret = Secret()
>>> bob_secret = Secret()
>>> expr = alice_secret * bob_secret * Scalar(2)

MODIFY THIS FILE.
"""

import base64
import random
from typing import Optional, List
from enum import Enum


ID_BYTES = 4


def gen_id() -> bytes:
    id_bytes = bytearray(
        random.getrandbits(8) for _ in range(ID_BYTES)
    )
    return base64.b64encode(id_bytes)


class OperationType(Enum):
    ADD = '+'
    MUL = '*'
    SUB = '-'


class Expression:
    """
    Base class for an arithmetic expression.
    """

    def __init__(
            self,
            id: Optional[bytes] = None # this should be a unique identifier for the expression (I suppose that multiple expressions can be run paralelly in the network)
        ):
        # If ID is not given, then generate one.
        if id is None:
            id = gen_id()
        self.id = id

    def __add__(self, other):
        return Operation(self, other, OperationType.ADD)

    def __mul__(self, other):
        return Operation(self, other, OperationType.MUL)

    def __sub__(self, other):
        return Operation(self, other, OperationType.SUB)

    def __hash__(self):
        return hash(self.id)

    def is_Scalar(self):
        return False
    def is_Secret(self):
        return False

    # Feel free to add as many methods as you like.


class Scalar(Expression):
    """Term representing a scalar finite field value."""

    def __init__(
            self,
            value: int,
            id: Optional[bytes] = None
        ):
        self.value = value
        super().__init__(id)


    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.value)})"


    def __hash__(self):
        return hash(self.id)

    def is_Scalar(self):
        return True
    def is_Secret(self):
        return False



class Secret(Expression):
    """Term representing a secret finite field value (variable)."""

    def __init__(
            self,
            value: Optional[int] = None,
            id: Optional[bytes] = None
        ):
        self.value = value
        super().__init__(id)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.value if self.value is not None else 'Null'})"
        )

    def is_Scalar(self):
        return False
    def is_Secret(self):
        return True

class Operation(Expression):
    """Term representing an operation between basic expression (i.e. sum between two secrets). It's a node of a tree"""
    def __init__(self, a: Expression, b: Expression, operand_type):
        self.a = a
        self.b = b
        self.operand_type = operand_type
        super().__init__()

    def __add__(self, other):
        return Operation(self, other, OperationType.ADD)

    def __mul__(self, other):
        return Operation(self, other, OperationType.MUL)

    def __sub__(self, other):
        return Operation(self, other, OperationType.SUB)

    def __repr__(self):
        ans = f"{repr(self.a)} {self.operand_type.value} {repr(self.b)}"
        if not self.operand_type == OperationType.MUL:
            ans = f"({ans})"
        return ans

    def get_operands(self) -> List[Expression]:
        return [self.a, self.b]

    def is_addition(self):
        return self.operand_type == OperationType.ADD

    def is_subtraction(self):
        return self.operand_type == OperationType.SUB

    def is_multiplication(self):
        return self.operand_type == OperationType.MUL

# Feel free to add as many classes as you like.
