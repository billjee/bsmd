# Message Intercepted
In this example two nodes are sharing information. The node A request mobility data from node B, and the messages will be intercepted by an external third party 
The example follows the next steps
  1. Node A and Node B are created
  2. The Node A request to the Node B his GPS traces and travel time.
      1. When the node A send the message for requesting the information the message is intercepted. This interception happen in the function `alterfile()`. The function simulate a third party intercepting the message and altering the contents of the message
      1. When the node B receive the altered message an error occurs which mean that the message was tampered by a third party so Node B cannot read the message and therefore cannot share information with node A. **Note:** comment line 53 to run the following steps
  3. The node B reads what information the Node A wants and by using a *smart contract* the node B send to the node A the solicited information
       1. When the node B send his mobility data to the node A the messages is intercepted by a third party. This interception happen in the function `interception()`. The function simulate a third party intercepting the message and trying to read the information
       2. When the third party tries to open the message an error occurs since the interceptor does not have the verification key **Note:** comment line 57 to run the following step of the example
  4. The node A read the mobility data of the Node B

## Run test
1. In terminal run 
```
pyton3 msgIntercepted.py
```
