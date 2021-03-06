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
from typing import Optional
from enum import Enum


ID_BYTES = 4


def gen_id() -> bytes:
    id_bytes = bytearray(
        random.getrandbits(8) for _ in range(ID_BYTES)
    )
    return base64.b64encode(id_bytes)


class OperandType(Enum):
    ADD =  'add'
    MUL = 'mul'
    SUB = 'sub'


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
        raise NotImplementedError("You need to implement this method.")


    def __sub__(self, other):
        raise NotImplementedError("You need to implement this method.")


    def __mul__(self, other):
        raise NotImplementedError("You need to implement this method.")


    def __hash__(self):
        return hash(self.id)


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

    def isScalar(self):
        return True

    def isSecret(self):
        return False

    def isOperand(self):
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

    def __add__(self, other):
        return Operands(self, other, OperandType.ADD)

    def __mul__(self, other):
        return Operands(self, other, OperandType.MUL)

    def __sub__(self, other):
        return Operands(self, other, OperandType.SUB)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.value if self.value is not None else ''})"
        )
    def isScalar(self):
        return False
    def isSecret(self):
        return True
    def isOperand(self):
        return False

class Operands(Expression):
    """Term representing an operation between basic expression (i.e. sum between two secrets). It's a node of a tree"""
    def __init__(self, a: Expression, b: Expression, operand_type):
        self.a = a
        self.b = b
        self.operand_type = operand_type
        super().__init__()

    def __add__(self, other):
        return Operands(self, other, OperandType.ADD)

    def __mul__(self, other):
        return Operands(self, other, OperandType.MUL)

    def __sub__(self, other):
        return Operands(self, other, OperandType.SUB)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.operand_type.name})"
        )
    #Helper function for descending the ast
    def isScalar(self):
        return False
    def isSecret(self):
        return False
    def isOperand(self):
        return True
    def retOperands(self):
        return [self.a, self.b]
    def retOperation(self):
        return self.operand_type

# Feel free to add as many classes as you like.
