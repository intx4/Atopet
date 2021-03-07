"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

from typing import (
    Dict,
)

import pickle

from communication import Communication
from expression import (
    Expression,
    Secret,
    Scalar,
    Operation
)
from protocol import ProtocolSpec
from secret_sharing import(
    split_secret_in_shares,
    Share
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

    is_scalar_additioner = False
    def __init__(
            self,
            client_id: str,
            server_host: str,
            server_port: int,
            protocol_spec: ProtocolSpec,
            value_dict: Dict[Secret, int]
        ):
        protocol_spec.participant_ids.sort()
        if protocol_spec.participant_ids[0] == client_id:
            SMCParty.is_scalar_additioner = True
        self.comm = Communication(server_host, server_port, client_id)
        self.client_id = client_id
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict


    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """
        self.init_secret_sharing()
        my_share = self.process_expression(self.protocol_spec.expr)
        self.comm.publish_message('done', pickle.dumps(my_share))
        shares = []
        for client_id in self.protocol_spec.participant_ids:
            shares.append(pickle.loads(self.comm.retrieve_public_message(client_id,'done')))
        return sum(shares)


    def init_secret_sharing(self):
        other_clients_ids = self.protocol_spec.participant_ids
        for key in self.value_dict.keys():
            secret_value = self.value_dict[key]
            shares = split_secret_in_shares(secret_value, len(other_clients_ids), key.id)
            for client_id, share in zip(other_clients_ids, shares):
                serialized_share = pickle.dumps(share)
                self.comm.send_private_message(client_id, key.id, serialized_share)


    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression, scalar_mult = True
        ) -> Share:
        if isinstance(expr, Operation):
            a, b = expr.get_operands()
            a = self.process_expression(a)
            b = self.process_expression(b)
            if expr.is_addition():
                return a+b
            elif expr.is_subtraction():
                return a-b
            elif expr.is_multiplication():
                return a*b
            else:
                raise RuntimeError("Operation expr not known")

        elif isinstance(expr, Secret):
            share = pickle.loads(self.comm.retrieve_private_message(expr.id))
            return share

        elif isinstance(expr, Scalar):
            pass
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.

    # Feel free to add as many methods as you want.
