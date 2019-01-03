# Spoofing credential
The example follows the next steps
1. Three nodes are created: Ryerson, Government and User
2. Government issues a credential to University to validate that University is a node to be trusted
3. University spoof his credential
3. The program will mark an error since the credential of the University was obtained outside the blockchain

Note: Comment from line 311 to 322 and watch how the program successfully execute since the credential was obtained directly from the blockchain


## Run test
1. Create a [virtual enviroment](https://docs.python-guide.org/dev/virtualenvs/)
2. In terminal type: 
```
pyton3 verification.py
```
