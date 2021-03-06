## Instructions
Install Indy using this [guide](https://github.com/hyperledger/indy-sdk#installing-the-sdk)

1. Create a population sample
```
pyton3 createpopulation.py
```
2. Create wallets for nodes
```
pyton3 createWalletsANDpool.py
```
3. Install a six node Indy blockchain. This blockchain will run in three cores of the computer
   1. Clone the [indy-sdk](https://github.com/hyperledger/indy-sdk) project
   2. In the cloned indy-sdk replace the file `indy-pool.dockerfile` contained in the “ci” folder with the [indy-pool.dockerfile](indy-pool.dockerfile) file of this project
   3. Run the blckchain in three cores
    ```
     docker build -f ci/indy-pool.dockerfile -t indy_pool .
     docker run –cpuset-cpus="0,1,2" -itd -p 9701-9712:9701-9712 indy_pool
    ```
4. Run the simulation in the remaining cores (5 cores).
    ```
     taskset -c 3,4,5,6,7 pyton3 populationExp.py
    ```
5. The output of the simulation is in the file *results.log*

For running the simulation with a different population size modify the line 14 of the file [createpopulation.py](createpopulation.py) and repeat steps 1 and 4. 
