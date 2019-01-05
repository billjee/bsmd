## Instructions for setting the blockchain
1. Create 10 Ubuntu 16.04 t3.medium virtual machines in AWS. 
2. On each machine install Indy-node.
```
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 68DB5E88
sudo echo "deb https://repo.sovrin.org/deb xenial stable" >> /etc/apt/sources.list
sudo apt-get update
sudo apt-get install indy-node
```
3. On each machine run an Indy-node. To setup each node follow this [guide](https://github.com/hyperledger/indy-node/blob/master/docs/start-nodes.md#remote-test-network-example). The guide is for four nodes, you may need to adapt it to ten nodes.
4. Write the IP of each machine you will need it the following steps.
5. Make sure the corresponding ports are open in each machine. Each machine will use two ports for communicating with the others 

## Instructions for setting the Raspberry Pi (RPI)
1. On an SD card install the latest [raspbian lite](https://www.raspberrypi.org/downloads/raspbian/)
2. In the RPI install Indy-sdk using this [guide](https://github.com/hyperledger/indy-sdk/blob/master/doc/ubuntu-build.md). Make sure to compile the software using `cargo build --release`, otherwise the simulation may not run
3. On the RPI put the files createWalletsANDpoolRPI.py, createpopulation.py, msgTwoNodesRPI.py, populationExp.py, start.sh     into and utils.py in the folder /home/pi/blockchain/. Create the folder /home/pi/blockchain/msg
4. Modify the file [utils.py](utils.py) with the corresponding IPs of the EC2 Virtual Machines 
5. Create a population sample. Run
```
pyton3 createpopulation.py
```
6. Create wallets for nodes. Run
```
pyton3 createWalletsANDpoolRPI.py
``` 
7. Make sure the RPI automatically connect to the Internet when boot
9. Create cron-job such that the RPI run the file [start.sh](start.sh) on boot
10. Turn of the RPI and create as many copies of the SD card as need it

## Instructions for running the simulation
1. Run the blockchain on the EC2 Virtual Machines. Amazon has a hard limit of 5 Static IP if you turn off the VM the some IP may change. If for any reason you turn off the machines prior running the experiment you may need to update the [utils.py](utils.py).py on each RPI 
2. Plug all the RPIs
3. The output of the simulation is on the file results.log located on each RPI 
