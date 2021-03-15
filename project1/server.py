"""
Trusted server that should help SMC client to communicate.
You should not need to change this file.
"""

import collections
import sys
from os import environ
from typing import Dict, List, Optional, Tuple

from flask import Flask, request, Response, jsonify

from ttp import TrustedParamGenerator

from performance import Analyst

environ["WERKZEUG_RUN_MAIN"] = "true"
app: Flask = Flask("Trusted Third Party Server")
store: Dict[str, Dict[Tuple[str, str], bytes]] = collections.defaultdict(dict)
ttp: TrustedParamGenerator = TrustedParamGenerator()
analyst: Analyst = Analyst(True)


@app.route("/private/<sender_id>/<receiver_id>/<label>", methods=["POST"])
def send_private_message(sender_id: str, receiver_id: str, label: str):
    """
    The client send a private message to the server.
    """
    print(
        f"[ SEND     ] SENDER {sender_id} / LABEL {label} / RECEIVER {receiver_id}"
    )
    data = request.get_data()
    analyst.__increment_in__(len(data))

    _set_value("private", (receiver_id, label), data)
    return Response(status=200)


@app.route("/private/<receiver_id>/<label>", methods=["GET"])
def retrieve_private_message(receiver_id: str, label: str):
    """
    The client retrieve a private message from the server.
    """
    res = _get_value("private", (receiver_id, label))
    if res is not None:
        print(f"[ RETRIEVE ] RECEIVER {receiver_id} / LABEL {label}")
        analyst.__increment_out__(len(res))
        return res, 200

    return Response(status=404)


@app.route("/public/<sender_id>/<label>", methods=["POST"])
def publish_message(sender_id: str, label: str):
    """
    The client publish a public message on the server.
    """
    print(f"[ PUBLISH  ] SENDER {sender_id} / LABEL {label}")
    data = request.get_data()
    analyst.__increment_in__(len(data))
    _set_value("public", (sender_id, label), data)
    return Response(status=200)


@app.route("/public/<receiver_id>/<sender_id>/<label>", methods=["GET"])
def retrieve_public_message(receiver_id: str, sender_id: str, label: str):
    """
    The client retrieve a public message from the server.
    """
    res = _get_value("public", (sender_id, label))
    if res is not None:
        print(
            f"[ RETRIEVE ] RECEIVER {receiver_id}. LABEL {label} / SENDER {sender_id}"
        )
        analyst.__increment_out__(len(res))
        if label == 'done':
            analyst.__log__()
        return res, 200
    return Response(status=404)


@app.route("/shares/<client_id>/<op_id>", methods=["GET"])
def retrieve_share(client_id: str, op_id: str):
    """
    The client retrieve Beaver triplets generated by the server.
    """
    shares = ttp.retrieve_share(client_id, op_id)
    data = jsonify([share.value for share in shares])
    analyst.__increment_out__(sys.getsizeof(data))
    return data, 200 #previously bn instead of value


def _set_value(pool: str, channel: Tuple[str, str], data: bytes) -> None:
    """
    Push data to a channel in a given pool and send an event.
    """
    store[pool][channel] = data


def _get_value(pool: str, channel: Tuple[str, str]) -> Optional[bytes]:
    """
    Subscribe to a channel in a given pool and get it once ready.
    """
    if channel not in store[pool]:
        return None
    return store[pool][channel]


def run(host: str, port: int, participants: List[str]) -> None:
    """
    Register the participants, then run the server.
    """
    analyst.__set_num__(len(participants))
    for participant in participants:
        ttp.add_participant(participant)
    app.run(host, port)



def main(args: List[str]) -> None:
    """
    Entrypoint of the program.
    """
    run("localhost", 5000, args)


if __name__ == "__main__":
    main(sys.argv[1:])
