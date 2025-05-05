# Simple secure broadcast chat
This is script python to create Private Secure Broadcast Chat. We can broadcast to all connected user/client. Before message received to another client, server will decrypt and check integrity of messsage and user. 
Only member/people who know this algorithm (in this case: ECDH SECO256k1, SHA256, DES) can join and broadcast chat. You can custom the algorithm to make your own secure chat.

## File Structure on Client / Server side

Client side:
Client.py and crypto_utils.py on same folder

Server side:
server.py and crypto_utils.py on same folder

## Requirement
- Python 3.6+
- Import module ecdsa, pycryptodome (pip install ecdsa pycryptodome)
- 
## PREVIEW WORKFLOW:
![WorkFlow](https://github.com/user-attachments/assets/05b828e9-fdb6-4a28-9e6c-070e2e182b82)
