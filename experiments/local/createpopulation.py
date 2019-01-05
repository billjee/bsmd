import logging
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

LOG_FILENAME = 'results.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO)

# Normal distribution of messages per person
mean1 = 9360
sd1 = 2350

persons = 10
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
coefficients = np.array([0.65, 0.8, 0.65])
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

logging.info("Person in total " + str(len(messagesEachPerson)))
logging.info("Minimun number of messages per person " + str(int(round(min(messagesEachPerson)))))
logging.info("Maximun number of messages per person " + str(int(round(max(messagesEachPerson)))))
logging.info("############################")

yB, xB, _ = ax2.hist(hourOfDay, bins=bin, density=False)


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


messagesPerMin = msgInt[startofList:endofList]

np.savetxt('msgPerMin.txt', messagesPerMin, fmt='%d')
print('done')
