## Intructions for running messages experiment
1. Create a [virtual enviroment](https://docs.python-guide.org/dev/virtualenvs/)
2. In terminal type: 
```
pyton3 nodeExp.py
```

## Intructions for running nodes experiment
1. Create a [virtual enviroment](https://docs.python-guide.org/dev/virtualenvs/)
2. For runing the experiment with two nodes type in terminal: 
```
for x in 1; do (python3 msgExp.py) & done
```
3. For runing the experiment with n (n is even) nodes type in terminal: 
```
for x in {1..n/2}; do (python3 msgExp.py) & done
```
