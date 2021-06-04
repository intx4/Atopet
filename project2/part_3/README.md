# Part 3

## Traces
In order to capture the traces we considered a server with 5 different types of POIs. We then ran a client that would request all the possible combinations
of these POIs and captured each client request server response attempts one by one.

## Structure 

### Credentials
the credentials that will be used for the server and client are already present under `key.sec`, `key.pub`, `key-client.pub` and `anon.cred`

### Classifier.txt
Place containing the results of the classifier run on the traces features.

### generate_traces.sh
Is a script used to generate the captured communication traces between the client and the tor guard node.

### repair_failed_runs.sh
Is a script that must be ran after `generate_traces.sh` in order to repair traces captured that failed due to a communication error in the network.

### Finger_printing
The finger_printing repository is where the trace collections as well as logic external to the capture scripts are located.
We did not include the raw and filtered file capture as their combine total size was way too big for the submission. 

#### generate_run.py
This file was used to crate part of the `run_commands` files that contains the requests that will be sent by the client to the server whose our malicious 3rd party will be eavesdropping on.

#### filter.sh
This script is responsible for removing the noise in the captured files. and put them in the `filtered` folder

#### feature_extraction.ipynb
Is a jupyter script responsible for extracting features out of the filtered captures and store them in `features.csv`.

## Running the capture and feature extractions
*Note that in this example only 30 traces per cell will be generated*

1. run `docker-compose build`
2. `docker-compose up -d`
3. `chmod -R 777 ./finger_printing`
4. `docker-compose exec server bash`
5. `cd server && python3 server.py run`
6. Then open a new terminal and in the same directory run `docker-compose exec client bash`
7. run `cd client && ./generate_traces.sh`
8. Once completed run `./repair_failed_runs.sh`
9. `cd finger_printing`
10. `./filter.sh`
11. Open `feature_extractions.ipynb` and run all cells
12. `cd ../`
13. `python3 fingerprinting.py` dump the results in `classifier_score.txt`.