## Instructions for running messages experiment (experiment 1 in papper)
1. Create a [virtual environment](https://docs.python-guide.org/dev/virtualenvs/)
2. In terminal type: 
```
pyton3 nodeExp.py
```

## Instructions for running nodes experiment (experiment 2 in papper)
1. Create a [virtual environment](https://docs.python-guide.org/dev/virtualenvs/)
2. For running the experiment with two nodes type in terminal: 
```
for x in 1; do (python3 msgExp.py) & done
```
3. For running the experiment with n (n is even) nodes type in terminal: 
```
for x in {1..n/2}; do (python3 msgExp.py) & done
```
