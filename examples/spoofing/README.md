# Spoofing identity
1. Three nodes are created: Ryerson, Government and User
2. Government issues a credential to University to validate that University is a node to be trusted
3. University spoof his credential before obtaining the application proof for connecting with the User
   1. The output of the program will show and error since the credential of the University does not match with the registries in the ledger. **Note**: Comment lines 311--322 and to run the following steps
3. University spoof his credential after obtaining the application proof for connecting with the User
   1. The output of the program will show an error since when User compare the credential of the University it will not match with the registries in the ledger. **Note**: Comment lines 369--2012 and watch how the program successfully execute since the credential sent by the University match with the registry of the ledger.
  
This two step verification make hard for malicious node to spoof his identity, since one verification is performed by an external node. The only change a Node has to spoof his identity is to tamper the blockchain which, for now, is nearly impossible.

## Run test
1. Setup your indy development virtual machine. Follow this [guide](https://github.com/hyperledger/indy-sdk/blob/master/doc/how-tos/prerequisites.md) 
2. In terminal type: 
```
pyton3 verification.py
```

