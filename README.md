# A Mutual Authentication Protocol for Secure Vehicle-to-Vehicle Direct Communication Channels

###### _Submitted in partial fulfillment of the requirements for the degree of Master of Science of University College London_

## Proof of concept of the proposed protocol

### Instructions

To run the proof of concept implemented, you need **Python 3.9** on your computer.

We recommend installing the required libraries in a virtual environment. See <https://docs.python.org/3/library/venv.html>

To install all the required libraries, run the following command on your terminal in the implementation folder:
`pip install -r requirements.txt`

There are two different modes for our script. The run mode allows you to run the authentication protocol successfully, thus at the end of it the two vehicles would be able to exchange messages. The second mode is the test mode. It allows you to see a demonstration of the Man-in-the-Middle attack described in Section \ref{sec:security-analysis. At the end of it, the two vehicles will not authenticate, thus they will end their communication without exchanging any message.

RUN MODE: `python3 proposal.py -r address:port`

TEST MODE: `python3 proposal.py -t address:port address:port`
where an example for _address:port_ could be _localhost:3000_.

To see in details the data exchanged in each message of the authentication progress, add the `-d` flag to the command you wish to run.