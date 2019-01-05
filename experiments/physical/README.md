## Instructions for installing the blockchain
1. Create 10 Ubuntu 16.04 *t3.medium* Virtual Machines in AWS. 
2. On each  Virtual Machine (VM) install Indy-node.
```
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 68DB5E88
sudo echo "deb https://repo.sovrin.org/deb xenial stable" >> /etc/apt/sources.list
sudo apt-get update
sudo apt-get install indy-node
```
3. On each VM run an Indy-node. To install the nodes follow this [guide](https://github.com/hyperledger/indy-node/blob/master/docs/start-nodes.md#remote-test-network-example). The guide is for four nodes, you may need to adapt it to ten nodes.
4. Write the IP of the VMs, you will need them the following steps
5. Make sure the corresponding ports of the VMs are [open](https://stackoverflow.com/questions/17161345/how-to-open-a-web-server-port-on-ec2-instance). Each VM will use two ports for communicating with the others. 

## Instructions for setting the Raspberry Pi (RPI)
1. On a SD card install the latest [raspbian lite](https://www.raspberrypi.org/downloads/raspbian/)
2. Turn-on the RPI and install Indy-sdk. Follow this [guide](https://github.com/hyperledger/indy-sdk/blob/master/doc/ubuntu-build.md). Make sure to compile the Indy using `cargo build --release`, otherwise the simulation may not run
3. Copy the files [createWalletsANDpoolRPI.py](createWalletsANDpoolRPI.py), [createpopulation.py](createpopulation.py), [msgTwoNodesRPI.py](msgTwoNodesRPI.py), [populationExp.py](populationExp.py), [start.sh](start.sh) and [utils.py](utils.py) in the folder `/home/pi/blockchain/`. Create the folder `/home/pi/blockchain/msg`
4. Modify the file [utils.py](utils.py) with the corresponding IPs of the VMs 
4. Give executable permission to the file *start.sh*
```
sudo chmod +x start.sh
```
5. Create a population sample. Run
```
pyton3 createpopulation.py
```
6. Create wallets for nodes. Run
```
pyton3 createWalletsANDpoolRPI.py
``` 
7. Make sure the RPI [automatically connect](https://weworkweplay.com/play/automatically-connect-a-raspberry-pi-to-a-wifi-network/) to the Internet when boot
9. Create cron-job such that the RPI run the file [start.sh](start.sh) on [boot](https://www.raspberrypi.org/documentation/linux/usage/cron.md)
10. Turn-off the RPI and create as many copies of the SD card as need it

## Instructions for running the simulation
1. Run the blockchain on the EC2 Virtual Machines. Amazon has a hard limit of 5 Static IP if you turn off the VM the some IP may change. If for any reason you turn off the machines prior running the experiment you may need to update the [utils.py](utils.py).py on each RPI 
2. Plug all the RPIs
3. The output of the simulation is on the file *results.log* located on each RPI 
