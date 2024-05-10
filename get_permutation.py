from numpy import array, savetxt
from random import shuffle, choice 
from main import BLOCK_SIZE, KEY_SIZE, b2h

KEY = [choice(('0', '1')) for _ in range(KEY_SIZE)]
KEY = b2h(''.join(KEY), KEY_SIZE//4)

IV = [choice(('0', '1')) for _ in range(BLOCK_SIZE)]
IV = b2h(''.join(IV))

IP = list(range(BLOCK_SIZE))
shuffle(IP)

FP = list(range(BLOCK_SIZE//2))
shuffle(FP)

KP = list(range(KEY_SIZE))
shuffle(KP)

IP_INV = [0]*BLOCK_SIZE
for i in range(BLOCK_SIZE):
    IP_INV[IP[i]] = i


for i in [[IP, 'IP'], [IP_INV, 'IP_INV'], [FP, 'FP'], [KP, 'KP']]:
    savetxt(f'{i[1]}.txt', array(i[0]), fmt='%d')
    
for i in [ [[KEY], 'KEY'], [[IV], 'IV'] ]:
    savetxt(f'{i[1]}.txt', array(i[0]), fmt='%s')

# print(f"KEY = '{KEY}'\nIP = {IP}\nIP_INV  = {IP_INV}\nIV = '{IV}'\nFP = {FP}\nKP = {KP}")



