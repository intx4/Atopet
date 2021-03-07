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
        self.my_secret_id = b"" #stores the b64 id of the secret I generated to know whether to fetch share localy.
        self.my_secret_share = Share(0) #share of my secret


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

    """Distribute shares of my secret among other parties"""
    def init_secret_sharing(self):
        other_clients_ids = self.protocol_spec.participant_ids
        #isn't value_dict just one value? (ours)
        for key in self.value_dict.keys():
            secret_value = self.value_dict[key]
            shares = split_secret_in_shares(secret_value, len(other_clients_ids), key.id)
            for client_id, share in zip(other_clients_ids, shares):
                if self.client_id != client_id:
                    serialized_share = pickle.dumps(share)
                    self.comm.send_private_message(client_id, str(key.id), serialized_share)
                else:
                    #No no, don't touch me there. This is, my local share!
                    self.my_secret_share = share
                    self.my_secret_id = key.id



    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression, scalar_addition = False, secret_mul = False
        ) -> Share:
        scalar_addition = False
        if isinstance(expr, Operation):
            a, b = expr.get_operands()
            if expr.is_addition():
                if isinstance(a, Scalar) or isinstance(b, Scalar):
                    scalar_addition = True
                a = self.process_expression(a, scalar_addition)
                b = self.process_expression(b, scalar_addition)
                return a.__add__(b)
            elif expr.is_subtraction():
                if isinstance(a, Scalar) or isinstance(b , Scalar):
                    scalar_addition = True
                a = self.process_expression(a, scalar_addition)
                b = self.process_expression(b, scalar_addition)
                return a.__sub__(b)
            elif expr.is_multiplication():
                # TO DO. Distinguish if is a multiplication between two secrets
                """
                a = self.process_expression(a)
                b = self.process_expression(b)
                return a.__mul__(b)
                """
                raise  RuntimeError("Lazy programmers did not implement multiplication")
            else:
                raise RuntimeError("Operation expr not known")

        elif isinstance(expr, Secret):
            if expr.id != self.my_secret_id:
                return pickle.loads(self.comm.retrieve_private_message(str(expr.id)))
            else:
                return self.my_secret_share


        elif isinstance(expr, Scalar):
            if scalar_addition:
                if self.is_scalar_additioner:
                    return Share(expr.value, expr.id)
                else:
                    return Share(0, expr.id)
            else:
                return Share(expr.value, expr.id)
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.

    # Feel free to add as many methods as you want.
