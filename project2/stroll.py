"""
Classes that you need to complete.
"""

from credential import *
# Optional import
from serialization import jsonpickle
#from server import PUBLIC_KEY, SECRET_KEY

# Type aliases
class State:
    """ Private state after issue request """
    def __init__(self, t, private_key, attribute_map):
        self.blinding_factor = t
        self.private_key = private_key
        self.attribute_map = attribute_map

class ABC:
    """ Attribute based credential to be dumped to file """
    def __init__(self, client_sk: int, client_attrs: AttributeMap, signature: Signature):
        self.client_sk = client_sk
        self.client_attrs = client_attrs
        self.sigma = signature.sigma
        
class Server:
    """Server"""
    #PUBLIC_KEY = PublicKey
    #SECRET_KEY = SecretKey
    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        #if PUBLIC_KEY is None or SECRET_KEY is None:
            #raise ValueError("Public or Secret ye not set")
        #Server.PUBLIC_KEY = PUBLIC_KEY
        #Server.SECRET_KEY = SECRET_KEY

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
        sk, pk = generate_key(subscriptions)
        e_sk = jsonpickle.encode(sk).encode()
        e_pk = jsonpickle.encode(pk).encode()
        
        return e_sk, e_pk

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
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
        subscriptions.append(username) #accordingly to server.py setup phase
        request = jsonpickle.decode(issuance_request.decode(), classes=IssueRequest)
        sk = jsonpickle.decode(server_sk.decode(), classes=SecretKey)
        pk = jsonpickle.decode(server_pk.decode(), classes=PublicKey)
        
        sigma = sign_issue_request(sk, pk, request, subscriptions)
        
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
        pk = jsonpickle.decode(server_pk.decode(), classes=PublicKey)
        disclosure_proof = jsonpickle.decode(signature.decode(), classes=DisclosureProof)
        return verify_disclosure_proof(pk, disclosure_proof, revealed_attributes, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################


    def prepare_registration(
            self,
            server_pk: bytes,
            username: str, #useless here
            subscriptions: List[str],
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
        request, state = create_issue_request(pk, subscriptions)
        
        return jsonpickle.encode(request).encode(), state
        
    def process_registration_response(
            self,
            server_pk: bytes, #useless
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
        
        response = jsonpickle.decode(server_response.decode(), classes=Signature)
        t = private_state.blinding_factor
        client_attributes = private_state.attribute_map
        client_sk = private_state.private_key
        
        signature = obtain_credential(t, response)
        if not signature.is_valid():
            raise Exception("Server could not issue a credential for chosen subscriptions!")
        
        credentials = ABC(client_sk=client_sk, client_attrs=client_attributes, signature=signature)
        
        return jsonpickle.encode(credentials).encode()


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
        pk = jsonpickle.decode(server_pk.decode(), classes=PublicKey)
        anon_creds = jsonpickle.decode(credentials.decode(), classes=ABC)
        request = create_disclosure_proof(pk, anon_creds.sigma, anon_creds.client_sk, anon_creds.client_attrs, types, message)
        
        return jsonpickle.encode(request).encode()
