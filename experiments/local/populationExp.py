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


messages = np.random.normal(mean1, sd1, persons)

messagesEachPerson = messages.astype(int)

logging.info("total messages in a day: " + str(sum(messagesEachPerson)))

# Normal distribution of messages in a day
distributions = [
    {"type": np.random.normal, "kwargs": {"loc": 8, "scale": 2.3}},
    {"type": np.random.normal, "kwargs": {"loc": 13, "scale": 3.35}},
    {"type": np.random.normal, "kwargs": {"loc": 18, "scale": 2.3}},
]
coefficients = np.array([0.7, 0.91, 0.7])
coefficients /= coefficients.sum()  # in case these did not add up to 1
sample_size = sum(messagesEachPerson)

num_distr = len(distributions)
data = np.zeros((sample_size, num_distr))
for idx, distr in enumerate(distributions):
    data[:, idx] = distr["type"](size=(sample_size,), **distr["kwargs"])
random_idx = np.random.choice(np.arange(num_distr), size=(sample_size,), p=coefficients)
hourOfDay = data[np.arange(sample_size), random_idx]

# Get the number of bins
longitudDay = abs(round(min(hourOfDay))) + abs(round(max(hourOfDay)))
floatBin = longitudDay * 60
bin = int(round(floatBin))

fig = plt.figure()
ax1 = fig.add_subplot(2, 1, 1)
ax2 = fig.add_subplot(2, 1, 2)

ax1.hist(messagesEachPerson, bins=100, density=True)
ax1.set_xlabel('Messages per person')
ax1.set_ylabel('Frequency')
logging.info("Person in total " + str(len(messagesEachPerson)))
logging.info("Minimun number of messages per person " + str(int(round(min(messagesEachPerson)))))
logging.info("Maximun number of messages per person " + str(int(round(max(messagesEachPerson)))))
logging.info("############################")

yB, xB, _ = ax2.hist(hourOfDay, bins=bin, density=False)
ax2.set_xlabel('Time of the day')
ax2.set_ylabel('Number of messages')
ax2.xaxis.set_major_formatter(ticker.FormatStrFormatter('%0.1f'))

logging.info("Number of messages in a day " + str(sum(yB)))
logging.info("Maximun number of messages in a minute " + str(int(round(yB.max()))))
logging.info("Maximun number of nodes sending messages in a minute " + str(int(round(yB.max() / 12))))
print("Maximun number of nodes sending messages in a minute " + str(int(round((yB.max() / 12) + 1))))
startTime = int(round(xB.min()))
endTime = int(round(xB.max()))
logging.info("Start time: " + str(startTime))
logging.info("End time: " + str(endTime))
# plt.show()


# sublist for getting messages per minute in the day
msgInt = yB.astype(int)

startofList = 0
endofList = 0
if startTime >= 0:
    startofList = 0
else:
    startofList = abs(startTime) * 60

if endTime - 24 < 0:
    endofList = bin
else:
    endofList = bin - ((endTime - 24) * 60)

# Given a pupulation get normaly distributed random numbers such that the numbers closest to the median
# are the ones whom are sendig messages all day
# Repeats until a number within the scale is found.
# x = np.arange(-1, persons + 1)
# xU, xL = x + 50, x - 50
# prob = ss.norm.cdf(xU, scale=300) - ss.norm.cdf(xL, scale=300)
# prob = prob / prob.sum()  # normalize the probabilities so their sum is 1
# nums = np.random.choice(x, size=100000, p=prob)
# yB, xB, _  = plt.hist(nums, bins=len(x))
# print(xB)
# print(nums.min(), nums.max())
# plt.show()
#
messagesPerMin = msgInt[startofList:endofList]
# print(bin, startofList, endofList)
# print(len(messagesPerMin))
# print(messagesPerMin[:500])

# save array
np.savetxt('msgPerMin.txt', messagesPerMin, fmt='%d')


########################################################
########################################################
########################################################
########################################################
########################################################
########################################################


# load array
msgPerMin = np.loadtxt('msgPerMin.txt', dtype=int)
messagesPerMin = msgPerMin[420:600]
print("total messages: ", sum(messagesPerMin))
print("max messages: ", max(messagesPerMin))
# messagesPerMin = msgPerMin

# Loop trough messagesPerMin, f
# for each element in messagerForExp get
#   1. Uniform random number for the service providers
#   2. Normal random number for the users
#
# temporal for proving
# messagesPerMin = [50, 34, 22, 2, 44]
# messagesPerMin = [1083]
# messagesPerMin = [2, 2]
#
# persons = 5000
# providers = 30


# logging.info("participants: " + str(persons))
# print("participants: " + str(persons))
# minute = 1
# for message in messagesPerMin:
#     print("minute " + str(minute) + ", Mesages: " + str(message))
#     logging.info("minute " + str(minute) + ", Mesages: " + str(message))
#     # Given that a person could send 12 messages in a minute
#     # Divide the number of messages by 12 to get the number of active nodes at the minute
#     activeNodes = message // 12
#     # The reminder of the division are messages sent by one node but this node will
#     # no have enough messages to complete the 12 message per minute
#     msgOfOrphanNode = message % 12
#     log = "Minute: " + str(minute) + ", messages: " + str(message) + ", participants: " + str(activeNodes + 1) + ", at: " + str(datetime.datetime.now())
#     # print(log)
#     logging.info(log)
#     # Get the random set of nodes for transaction
#     # First given the active pair of nodes we get all pairs of nodes, i.e., 1 pair equal to 2 nodes and so on
#     # print(activeNodes)
#     nodesForTransacting = random.sample(range(1, persons + 20), activeNodes + 1)
#     # print(message, nodesForTransacting)
#     # create process list
#     processes = []
#     for i, node in enumerate(nodesForTransacting):
#         # Get a node for recivineg the messages
#         nodeForTransacting = random.randint(persons + 100, persons + providers + 100 + 2)
#         # Get did and keys nodeA
#         with open('wallets/' + str(node) + '_wallet.nfo') as csv_file:
#             csv_reader = csv.reader(csv_file, delimiter=',')
#             for row in csv_reader:
#                 NodeA_did = row[0]
#                 NodeA_key = row[1]
#         # Get did and keys nodeB
#         with open('wallets/' + str(nodeForTransacting) + '_wallet.nfo') as csv_file:
#             csv_reader = csv.reader(csv_file, delimiter=',')
#             for row in csv_reader:
#                 NodeB_did = row[0]
#                 NodeB_key = row[1]
#         if i == len(nodesForTransacting) - 1:
#             if msgOfOrphanNode == 0:
#                 continue
#             # nA, nB, messages, number, NodeA_did, NodeA_key, NodeB_did, NodeB_key
#             process = 'msgTwonodes.py ' + str(node) + ' ' + str(nodeForTransacting) + ' ' + str(msgOfOrphanNode) + ' '\
#                       + str(i) + ' ' + NodeA_did + ' ' + NodeA_key + ' ' + NodeB_did + ' ' + NodeB_key
#
#         else:
#             process = 'msgTwonodes.py ' + str(node) + ' ' + str(nodeForTransacting) + ' ' + '12' + ' ' + str(i) + ' ' +\
#                       NodeA_did + ' ' + NodeA_key + ' ' + NodeB_did + ' ' + NodeB_key
#         processes.append(process)
#
#     # Skip the case when there are no messages in the minute
#     if len(processes) == 0:
#         minute += 1
#         log = "Minute: " + str(minute) + " no messages in the batch"
#         logging.info(log)
#         continue
#     # Start proccess
#     # msgTwonodes.py nodeA, nodeB, messages, experiment
#     # processes = ('msgTwonodes.py 1 2 12 1', 'msgTwonodes.py 3 4 12 1')
#     processInPool = len(processes)
#     pool = Pool(processes=processInPool)
#     start = time.time()
#     pool.map(run_process, processes)
#     end = time.time()
#     timeElapsed = end - start
#     log = "Minute: " + str(minute) + ", messages: " + str(message) + ", Finish in: " + str(timeElapsed)
#     # print(log)
#     logging.info(log)
#     minute += 1
#     pool.close()

















# Given a pupulation get normaly distributed random numbers such that the numbers closest to the median
# are the ones whom are sendig messages all day
# Repeats until a number within the scale is found.
# x = np.arange(0, persons + 1)
# xU, xL = x + 50, x - 50
# prob = ss.norm.cdf(xU, scale=300) - ss.norm.cdf(xL, scale=300)
# prob = prob / prob.sum()  # normalize the probabilities so their sum is 1
# nums = np.random.choice(x, size=100000, p=prob)
# yB, xB, _  = plt.hist(nums, bins=len(x),density=True)
# print(yB.size)
# print(nums.min(), nums.max())


# rango = np.arange(0, 900)
# xU, xL = rango + 50, rango - 50
# prob = ss.norm.cdf(xU, scale=300) - ss.norm.cdf(xL, scale=300)
# prob = prob / prob.sum()  # normalize the probabilities so their sum is 1
# nums = np.random.choice(rango, size=1000, p=prob)
# print(nums)
#
# # nodes = np.random.choice(x, p=yB)
# plt.show()
