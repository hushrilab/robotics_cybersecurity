import sys
from termcolor import colored

def PrintColored(string, color):
    print(colored(string, color))

def PrintDynamic(string):
    sys.stdout.flush()

def RoundToNearest(n, m):
    try:
        r = n % m
        return n + m - r if r + r >= m else n - r
    except Exception as e:
        print(f"Error when processing: {e}")
