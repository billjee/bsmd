# Transaction between two nodes
1. Four nodes are created: Ryerson, Government, David, CompanyA
2. Government issues a credential to Ryerson to validate that Ryerson is a University and is a node to be trusted
3. Ryerson shows David the validated credential so David can trust Ryerson for exchanging information.
3. David accepts request from Ryerson
3. Ryerson ask David for information
   1. Ryerson ask for name, gender, address, mode, travel time and GPS. However the *smart contract* of David only accepts name, mode, travel, time and GPS. The transaction is rejected
   1. Ryerson ask for name, mode, travel time and GPS. The transaction is accepted by the *smart contract* and a channel of communication is opened to finish the transaction
   
## Run transaction
1. Setup your indy development virtual machine. Follow this [guide](https://github.com/hyperledger/indy-sdk/blob/master/doc/how-tos/prerequisites.md)  
2. In terminal type: 
```
pyton3 main.py
```
