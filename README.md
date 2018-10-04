# Reference
David Lopéz, Bilal Farooq (2018) A blockchain framework for smart mobility.	In the proceedings of IEEE International Smart Cities Conference 2018. https://arxiv.org/abs/1809.05785

# Blockchain for smart mobility
Blockchain framework for Smart Mobility Data-market (BSMD) is designed to solve the privacy, security and management issues related to the sharing of passively as well as actively solicited large-scale data. Data from the individuals, governments, universities and companies are distributed on the network and stored in a decentralized manner, the data transactions are recorded and must have the authorization of the owners.

For building the experiment of the BSMD we use the [Hyperledger indy-sdk](https://github.com/hyperledger/indy-sdk).

## Installation
In order to run the transaction example and the experiments, first you need to install a test network:

1. To install network in different computers follow [this guide](https://github.com/hyperledger/indy-node/blob/master/docs/start-nodes.md#create-a-network-and-start-nodes) (hard)
2. To install network in a single computer follow [this guide](https://github.com/hyperledger/indy-sdk#how-to-start-local-nodes-pool-with-docker) (easy)

Go to [transaction](/transaction) to see a transaction example or go to [experiments](/experiments) to run some stress test. 

## Built With

* [Hyperledger indy-sdk](https://github.com/hyperledger/indy-sdk) - The blokchain sdk
* [Python3](https://www.python.org/download/releases/3.0/) - source code

## Authors

* **David Lopez** [mitrailer](https://github.com/mitrailer)
* **Bilal Farooq** [billjee](https://github.com/billjee/)

## License

* Hyperledger indy-sdk and indy-node are licensed under the Apache License 2.0 - see the [LICENSE](https://github.com/hyperledger/indy-node/blob/master/LICENSE) file for details
* This project is licensed under the Apache License 2.0 - see the [LICENSE.md](LICENSE.md) file for details
