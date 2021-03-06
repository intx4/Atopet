"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

import collections
import json
from typing import (
    Dict,
    Set,
    Tuple,
    Union
)

from communication import Communication
from expression import *
from protocol import ProtocolSpec
from secret_sharing import(
    reconstruct_secret,
    share_secret,
    Share,
)

# Feel free to add as many imports as you want.

class SMCParty:
    """
    A client that executes an SMC protocol to collectively compute a value of an expression together
    with other clients.

    Attributes:
        client_id: Identifier of this client
        server_host: hostname of the server
        server_port: port of the server
        protocol_spec (ProtocolSpec): Protocol specification
        value_dict (dict): Dictionary assigning values to secrets belonging to this client.
    """

    def __init__(
            self,
            client_id: str,
            server_host: str,
            server_port: int,
            protocol_spec: ProtocolSpec,
            value_dict: Dict[Secret, int]
        ):
        self.comm = Communication(server_host, server_port, client_id)

        self.client_id = client_id
        self.identifier = self.client_identifier(self.client_id, self.protocol_spec.participant_ids)
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict

    """This will be useful in the ADD-K protocol. If my indentifier is 0, then I will add the constant"""
    def client_identifier(self, my_id, other_ids):
        i = 0
        for id in other_ids:
            if id == my_id:
                return i
            else:
                i += 1

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """

        #First of all, the party should send the shares of her secret to the other parties

        label, secret = self.value_dict.items()
        parties = self.protocol_spec.participant_ids

        shares = share_secret(secret, len(parties))
        for p, s in zip(parties, shares):
            self.comm.send_private_message(p, label + "_share", s.toJson())

        return self.process_expression(self.protocol_spec.expr).value
    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression
        ) -> Share:
        # if expr is an addition operation:
        #     ...
        if (expr.isOperand()):
            share = self.process_operand(self, expr)

        # if expr is a multiplication operation:
        #     ...

        # if expr is a secret:
        #     ...

        # if expr is a scalar:
        #     ...
        #
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.
        pass

    def process_operand(
            self,
            op: Operands
    ) -> Share:
        exprs = op.retOperands()

        shareA = self.process_expression(self, exprs[0])
        shareB = self.process_expression(self, exprs[1])

        if (op.operand_type == OperandType.ADD):
            return Share( (shareA.__add__(shareB)).value, shareA.num_shares)
        if (op.operand_type == OperandType.MUL):
            return Share( (shareA.__mul__(shareB)).value, shareA.num_shares)
        if (op.operand_type == OperandType.SUB):
            return Share( (shareA.__sub__(shareB)).value, shareA.num_shares)





