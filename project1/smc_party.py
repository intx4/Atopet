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
from time import sleep

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
        protocol_spec.participant_ids.sort() #add some consistency
        self.comm = Communication(server_host, server_port, client_id)
        self.client_id = client_id
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict
        self.my_secret_share = {} #share of my secret

    def is_additioner_client(self):
        return self.protocol_spec.participant_ids[0] == self.client_id

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """
        self.init_secret_sharing()
        my_share = self.process_expression(self.protocol_spec.expr)
        self.comm.publish_message('done', pickle.dumps(my_share))
        shares = []
        for client_id in self.protocol_spec.participant_ids:
            shares.append(pickle.loads(self.comm.retrieve_public_message(client_id ,'done')))
        return sum(shares)

    """Distribute shares of my secret among other parties"""
    def init_secret_sharing(self):
        other_clients_ids = self.protocol_spec.participant_ids
        #isn't value_dict just one value? (ours)
        for key in self.value_dict.keys():
            secret_value = self.value_dict[key]
            shares = split_secret_in_shares(secret_value, len(other_clients_ids), True)
            for client_id, share in zip(other_clients_ids, shares):
                if self.client_id != client_id:
                    serialized_share = pickle.dumps(share)
                    self.comm.send_private_message(client_id, str(key.id.__hash__()), serialized_share)
                else:
                    #No no, don't touch me there. This is, my local share!
                    self.my_secret_share[key.id.__hash__()] = share

    def process_expression(
            self,
            expr: Expression, is_multiplication=True
        ) -> Share:
        if isinstance(expr, Operation):
            a, b = expr.get_operands()
            if expr.is_addition():
                a = self.process_expression(a, False)
                b = self.process_expression(b, False)
                return a + b
            elif expr.is_subtraction():
                a = self.process_expression(a, False)
                b = self.process_expression(b, False)
                return a - b
            elif expr.is_multiplication():
                # Distinguish if is a multiplication between two secrets
                a = self.process_expression(a)
                b = self.process_expression(b)
                if a.is_secret_share() and b.is_secret_share():
                    print("Here")
                    # Beaver triplets Algorithm
                    # u = a, v = b, w = c and a = x, b = y
                    u, v, w = self.comm.retrieve_beaver_triplet_shares(str(expr.id.__hash__()))
                    u = Share(u, True)
                    v = Share(v, True)
                    w = Share(w, True)
                    # x = a - u that in protocol spec would be x - a
                    # y = b - v that in protocol spec would be y - b
                    x = a - u
                    y = b - v
                    self.comm.publish_message('beaver:x-a_' + str(expr.id.__hash__()), pickle.dumps(x))
                    self.comm.publish_message('beaver:y-b_' + str(expr.id.__hash__()), pickle.dumps(y))
                    print("Here")
                    # reconstruct locally x - a and y - b (where x = a, a = u, y = b, b = v)
                    for client_id in self.protocol_spec.participant_ids:
                        if self.client_id != client_id:
                            x = x + pickle.loads(self.comm.retrieve_public_message(client_id, 'beaver:x-a_' + str(expr.id.__hash__())))
                            y = y + pickle.loads(self.comm.retrieve_public_message(client_id, 'beaver:y-b_' + str(expr.id.__hash__())))
                    print("Here")
                    res = w + (a * y) + (b * x)
                    if self.is_additioner_client():
                        res = res - (x * y)
                    return res
                else:
                    return a * b
            else:
                raise RuntimeError("Operation expr not known")

        elif isinstance(expr, Secret):
            if expr.id.__hash__() in self.my_secret_share.keys():
                return self.my_secret_share[expr.id.__hash__()]
            else:
                return pickle.loads(self.comm.retrieve_private_message(str(expr.id.__hash__())))

        elif isinstance(expr, Scalar):
            # Return the constant value if and only if it's a multiplication or it's and addition and I'm the additioner.
            if not is_multiplication:
                if self.is_additioner_client():
                    return Share(expr.value, False)
                else:
                    return Share(0, False)
            else:
                return Share(expr.value, False)
