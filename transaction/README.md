# Transaction between two nodes
The example follows the next steps
1. Four nodes are created: Ryerson, Government, David, CompanyA
2. Government issues a credential to Ryerson to validate that Ryerson is a University and is a node to be trusted
3. Ryerson shows David the validated credential. David can trust Ryerson for exchanging information. David accepts request from Ryerson
3. Ryerson ask David for information
   1. Ryerson ask for name, gender, address, mode, travel time and GPS. However the smart contract of David only accepts name, mode, travel, time and GPS. The transaction is rejected
   1. Ryerson ask for name, mode, travel time and GPS. The transaction is accepted by the smart contract and a channel of communication is opened to finish the transaction
   
## Run transaction
1. Create a [virtual enviroment](https://docs.python-guide.org/dev/virtualenvs/)
2. In terminal type: 
```
pyton3 main.py
```
