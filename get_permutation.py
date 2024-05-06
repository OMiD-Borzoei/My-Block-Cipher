from random import shuffle, choice 
from test import BLOCK_SIZE, KEY_SIZE

KEY = [choice(('0', '1')) for _ in range(KEY_SIZE)]
KEY = ''.join(KEY)

IV = [choice(('0', '1')) for _ in range(BLOCK_SIZE)]
IV = ''.join(IV)
IV = hex(int(IV, 2))[2:].zfill(BLOCK_SIZE//4)

IP = list(range(BLOCK_SIZE))
shuffle(IP)

FP = list(range(BLOCK_SIZE//2))
shuffle(FP)

IP_INV = [0]*BLOCK_SIZE
for i in range(BLOCK_SIZE):
    IP_INV[IP[i]] = i


with open('constants.txt', 'w') as file:
    for i in [KEY, IV, IP, IP_INV, FP]:
        for j in i:
            file.write(str(j) + ',')
        file.write('\n')
        
 
print(f"KEY = '{KEY}'\nIP = {IP}\nIP_INV  = {IP_INV}\nIV = '{IV}'\nFP = {FP}")



