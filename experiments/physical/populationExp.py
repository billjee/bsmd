import numpy as np
import os
import random
import datetime
import logging
import time
import csv
from multiprocessing import Pool

LOG_FILENAME = '/home/pi/blockchain/results.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO)


def run_process(process):
    os.system('python {}'.format(process))


persons = 10
providers = 6

# load array
startLooping = 420
endLoopin = 600
msgPerMin = np.loadtxt('/home/pi/blockchain/msgPerMin.txt', dtype=int)
messagesPerMin = msgPerMin[startLooping:endLoopin]

logging.info("participants: " + str(persons))
print("participants: " + str(persons))

minute = startLooping + 1
for message in messagesPerMin:
    print("minute " + str(minute) + ", Mesages: " + str(message))
    logging.info("minute " + str(minute) + ", Mesages: " + str(message))
    # Given that a person could send 12 messages in a minute
    # Divide the number of messages by 12 to get the number of active nodes at the minute
    activeNodes = message // 12
    # The reminder of the division are messages sent by one node but this node will
    # no have enough messages to complete the 12 message per minute
    msgOfOrphanNode = message % 12
    log = "Minute: " + str(minute) + ", messages: " + str(message) + ", participants: " + str(activeNodes + 1) +\
          ", at: " + str(datetime.datetime.now())
    logging.info(log)
    # Get the random set of nodes for transaction
    # First given the active pair of nodes we get all pairs of nodes, i.e., 1 pair equal to 2 nodes and so on
    nodesForTransacting = random.sample(range(1, 60000), activeNodes + 1)
    # create process list
    processes = []
    for i, node in enumerate(nodesForTransacting):
        # Get a node for recivineg the messages
        nodeForTransacting = random.randint(persons, persons + providers)
        if i == len(nodesForTransacting) - 1:
            if msgOfOrphanNode == 0:
                continue
            process = 'msgTwoNodesRPI.py ' + str(node) + ' ' + str(node) + ' ' + str(msgOfOrphanNode)
        else:
            process = 'msgTwoNodesRPI.py ' + str(node) + ' ' + str(node) + ' ' + '12'
        processes.append(process)
        # print(process)

    # Skip the case when there are no messages in the minute
    if len(processes) == 0:
        minute += 1
        log = "Minute: " + str(minute) + " no messages in the batch"
        logging.info(log)
        continue
    processInPool = len(processes)
    poolFiles = Pool(processes = processInPool)
    start = time.time()
    poolFiles.map(run_process, processes)
    end = time.time()
    timeElapsed = end - start
    log = "Minute: " + str(minute) + ", messages: " + str(message) + ", Finish in: " + str(timeElapsed)
    logging.info(log)
    minute += 1
    poolFiles.close()
