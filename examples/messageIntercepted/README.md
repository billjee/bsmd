# Message Intercepted
The example follows the next steps
  1. Three nodes are created: Ryerson, Government and User
  2. Government issues a credential to University to validate that University is a node to be trusted
  3. University spoof his credential before obtaining the application proof for connection
      1. The output of the program will show "Wallet item not found" since the credential of the University does not match with the registries in the ledger. **Note**: Comment from line 311 to 322 and watch how the program successfully execute since the credential was obtained directly from the blockchain
  3. University spoof his credential after obtaining the application proof for connection
      1. When the user verifies the information sent by the University with the information in the ledger, the output of the program will show "AssertionError" since the credential of the University does not match with the registries in the ledger. **Note**: Comment from line 369 to line 2012 and watch how the program successfully execute since the credential sent by the University match with the registry of the ledger

## Run test
1. In terminal type: 
```
pyton3 msgIntercepted.py
```
