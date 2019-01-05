import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import os
import sys
import asyncio
import time
import random
import datetime
import json
import logging
import csv

from multiprocessing import Process
from multiprocessing import Pool
from indy import crypto, did, wallet
from random import randint


LOG_FILENAME = 'results.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO)


def run_process(process):
    os.system('python {}'.format(process))

# Normal distribution of messages per person
mean1 = 9360
sd1 = 2350

persons = 20
providers = 6

# load array
msgPerMin = np.loadtxt('msgPerMin.txt', dtype=int)
print("total messages: ", sum(messagesPerMin))
print("max messages: ", max(messagesPerMin))
messagesPerMin = msgPerMin

# Loop trough messagesPerMin, f
# for each element in messagerForExp get
#   1. Uniform random number for the service providers
#   2. Normal random number for the users

# temporal for proving

logging.info("participants: " + str(persons))
print("participants: " + str(persons))
minute = 1
for message in messagesPerMin:
    print("minute " + str(minute) + ", Mesages: " + str(message))
    logging.info("minute " + str(minute) + ", Mesages: " + str(message))
    # Given that a person could send 12 messages in a minute
    # Divide the number of messages by 12 to get the number of active nodes at the minute
    activeNodes = message // 12
    # The reminder of the division are messages sent by one node but this node will
    # no have enough messages to complete the 12 message per minute
    msgOfOrphanNode = message % 12
    log = "Minute: " + str(minute) + ", messages: " + str(message) + ", participants: " + str(activeNodes + 1) + ", at: " + str(datetime.datetime.now())
    # print(log)
    logging.info(log)
    # Get the random set of nodes for transaction
    # First given the active pair of nodes we get all pairs of nodes, i.e., 1 pair equal to 2 nodes and so on
    # print(activeNodes)
    nodesForTransacting = random.sample(range(1, persons + 20), activeNodes + 1)
    # print(message, nodesForTransacting)
    # create process list
    processes = []
    for i, node in enumerate(nodesForTransacting):
        # Get a node for recivineg the messages
        nodeForTransacting = random.randint(persons + 100, persons + providers + 100 + 2)
        # Get did and keys nodeA
        with open('wallets/' + str(node) + '_wallet.nfo') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                NodeA_did = row[0]
                NodeA_key = row[1]
        # Get did and keys nodeB
        with open('wallets/' + str(nodeForTransacting) + '_wallet.nfo') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                NodeB_did = row[0]
                NodeB_key = row[1]
        if i == len(nodesForTransacting) - 1:
            if msgOfOrphanNode == 0:
                continue
            # nA, nB, messages, number, NodeA_did, NodeA_key, NodeB_did, NodeB_key
            process = 'msgTwonodes.py ' + str(node) + ' ' + str(nodeForTransacting) + ' ' + str(msgOfOrphanNode) + ' '\
                      + str(i) + ' ' + NodeA_did + ' ' + NodeA_key + ' ' + NodeB_did + ' ' + NodeB_key

        else:
            process = 'msgTwonodes.py ' + str(node) + ' ' + str(nodeForTransacting) + ' ' + '12' + ' ' + str(i) + ' ' +\
                      NodeA_did + ' ' + NodeA_key + ' ' + NodeB_did + ' ' + NodeB_key
        processes.append(process)

    # Skip the case when there are no messages in the minute
    if len(processes) == 0:
        minute += 1
        log = "Minute: " + str(minute) + " no messages in the batch"
        logging.info(log)
        continue
    # Start proccess
    # msgTwonodes.py nodeA, nodeB, messages, experiment
    # processes = ('msgTwonodes.py 1 2 12 1', 'msgTwonodes.py 3 4 12 1')
    processInPool = len(processes)
    pool = Pool(processes=processInPool)
    start = time.time()
    pool.map(run_process, processes)
    end = time.time()
    timeElapsed = end - start
    log = "Minute: " + str(minute) + ", messages: " + str(message) + ", Finish in: " + str(timeElapsed)
    # print(log)
    logging.info(log)
    minute += 1
    pool.close()
