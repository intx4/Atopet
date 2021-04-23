"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple
from credential import Attribute
from credential import SecretKey, PublicKey, generate_key
from credential import IssueRequest, create_issue_request, sign_issue_request
# Optional import
from serialization import jsonpickle

# Type aliases
State = int #blinding factor

class Server:
    """Server"""
    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.pk = b"" # keys in serialized form
        self.sk = b""
        
        self.sk, self.pk = self.generate_ca(subscriptions)
        
    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        sk, pk = generate_key(len(subscriptions))
        e_sk = jsonpickle.encode(sk).encode()
        e_pk = jsonpickle.encode(pk).encode()
        
        return e_sk, e_pk

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str] #disclo
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        request = jsonpickle.decode(issuance_request.decode(), classes=IssueRequest)
        sk = jsonpickle.decode(server_sk.decode())
        pk = jsonpickle.decode(server_pk.decode())
        
        attrs = [Attribute(a) for a in subscriptions]
        sigma = sign_issue_request(sk, pk, request, attrs)
        
        return jsonpickle.encode(sigma).encode()
    
    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError()


    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        pk = jsonpickle.decode(server_pk.decode())
        attrs = [Attribute(a) for a in subscriptions]
        request, t = create_issue_request(pk, attrs)
        
        return jsonpickle.encode(request).encode(), t
        
    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError
