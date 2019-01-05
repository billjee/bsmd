#!/bin/bash
sleep 60
cd /home/pi/blockchain/
source venv/bin/activate
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/pi/indy-sdk/libindy/target/release
python3 populationExp.py
