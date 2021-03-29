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
        self.my_secret_shares = {} #share of my secret

    def is_additioner_client(self):
        return self.protocol_spec.participant_ids[0] == self.client_id

    def run(self):
        """
        The method the client use to do the SMC.
        """
        self.init_secret_sharing()
        if not self.protocol_spec.application :
            my_share = self.process_expression(self.protocol_spec.expr)
            self.comm.publish_message('done', pickle.dumps(my_share))
            shares = []
            for client_id in self.protocol_spec.participant_ids:
                shares.append(pickle.loads(self.comm.retrieve_public_message(client_id ,'done')))
            return sum(shares)
        else:
            operators = []
            iter = 0
            for e in self.protocol_spec.expr:
                my_share = self.process_expression(e)
                self.comm.publish_message('done'+str(iter), pickle.dumps(my_share))
                shares = []
                for client_id in self.protocol_spec.participant_ids:
                    shares.append(pickle.loads(self.comm.retrieve_public_message(client_id, 'done'+str(iter))))
                if iter == 0:
                    operators.append(sum(shares))
                else:
                    operators.append(sum(shares))
                iter += 1
            return operators[0]/operators[1]

    """Distribute shares of my secret among other parties"""
    def init_secret_sharing(self):
        other_clients_ids = self.protocol_spec.participant_ids
        #isn't value_dict just one value? (ours)
        for key in self.value_dict.keys():
            secret_value = self.value_dict[key]
            shares = split_secret_in_shares(secret_value, len(other_clients_ids))
            for client_id, share in zip(other_clients_ids, shares):
                if self.client_id != client_id:
                    serialized_share = pickle.dumps(share)
                    self.comm.send_private_message(client_id, str(key.id.__hash__()), serialized_share)
                else:
                    #No no, don't touch me there. This is, my local share!
                    self.my_secret_shares[key.id] = share

    def process_expression(
            self,
            expr: Expression
        ) -> Share:
        if isinstance(expr, Operation):
            a, b = expr.get_operands()
            if expr.is_addition():
                a = self.process_expression(a)
                b = self.process_expression(b)
                if a.is_secret_share() and b.is_secret_share():
                    return a+b
                elif self.is_additioner_client():
                    return a+b
                else:
                    if a.is_secret_share():
                        return a
                    else:
                        return b

            elif expr.is_subtraction():
                a = self.process_expression(a)
                b = self.process_expression(b)
                return a - b
            elif expr.is_multiplication():
                # Distinguish if is a multiplication between two secrets
                a = self.process_expression(a)
                b = self.process_expression(b)
                if a.is_secret_share() and b.is_secret_share():
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
                    # reconstruct locally x - a and y - b (where x = a, a = u, y = b, b = v)
                    for client_id in self.protocol_spec.participant_ids:
                        if self.client_id != client_id:
                            x = x + pickle.loads(self.comm.retrieve_public_message(client_id, 'beaver:x-a_' + str(expr.id.__hash__())))
                            y = y + pickle.loads(self.comm.retrieve_public_message(client_id, 'beaver:y-b_' + str(expr.id.__hash__())))
                    res = w + (a * y) + (b * x)
                    if self.is_additioner_client():
                        res = res - (x * y)
                    return res
                else:
                    return a * b
            else:
                raise RuntimeError("Operation expr not known")

        elif isinstance(expr, Secret):
            if expr.id in self.my_secret_shares.keys():
                return self.my_secret_shares[expr.id]
            else:
                return pickle.loads(self.comm.retrieve_private_message(str(expr.id.__hash__())))

        elif isinstance(expr, Scalar):
            return Share(expr.value, False)
