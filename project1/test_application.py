import time
from multiprocessing import Process, Queue

import pytest

from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run

from smc_party import SMCParty


def smc_client(client_id, prot, value_dict, queue):
    cli = SMCParty(
        client_id,
        "localhost",
        5000,
        protocol_spec=prot,
        value_dict=value_dict
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(server_args, *client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue)) for args in client_args]

    server.start()
    time.sleep(3)
    for client in clients:
        client.start()

    results = list()
    for client in clients:
        client.join()

    for client in clients:
        results.append(queue.get())

    server.terminate()
    server.join()

    # To "ensure" the workers are dead.
    time.sleep(2)

    print("Server stopped.")

    return results


def suite(parties, expr, expected):
    participants = list(parties.keys())

    prot = ProtocolSpec(expr=expr, participant_ids=participants)
    clients = [(name, prot, value_dict) for name, value_dict in parties.items()]

    results = run_processes(participants, *clients)

    for result in results:
        assert result == expected


"""
   This simple test aims to show our application circuit.
   It evaluates the average gpa of n student, who will privately
   provide their grades and, for each grade, the number of credits
   the course was worth. The circuit implementation is the following:

   f = (sum_0^N{grade_i*ects_i*100} / sum_0^N{ects_i})

   Note that:
    1 - the grades are multiplied by 100 in order to operate with Integers.
    2 - the division is computed after reconstructing the values for the
        two expressions of the circuit, in order to avoid defining a new
        kind of operation, the division mod FIELD.
"""
def test_appl():
    alice_grade = Secret()
    alice_ects = Secret()
    bob_grade = Secret()
    bob_ects = Secret()
    charlie_grade = Secret()
    charlie_ects = Secret()
    emilie_grade = 600
    emilie_ects = 7

    parties = {
        "Alice": {alice_grade: 525, alice_ects: 7},
        "Bob": {bob_grade: 475, bob_ects: 6},
        "Charlie": {charlie_grade: 550, charlie_ects: 5},
    }
    expr = []
    expr.append(alice_grade * alice_ects + bob_grade * bob_ects + charlie_grade * charlie_ects + Scalar(emilie_grade)*Scalar(emilie_ects))
    expr.append(Scalar(100)*(alice_ects + bob_ects + charlie_ects + Scalar(emilie_ects)))
    expected = ((525 * 7 + 475 * 6 + 550 * 5 + 600*7) / (100 * (7 + 6 + 5 + 7)))
    suite(parties, expr, expected)
