from random import shuffle, choice 
from main import BLOCK_SIZE



IV = [choice(('0', '1')) for _ in range(BLOCK_SIZE)]
IV = ''.join(IV)
IV = hex(int(IV, 2))[2:].zfill(BLOCK_SIZE//4)

IP = list(range(BLOCK_SIZE))
shuffle(IP)

IP_INV = [0]*BLOCK_SIZE
for i in range(BLOCK_SIZE):
    IP_INV[IP[i]] = i

print(f"IP: {IP}\nIP_INV: {IP_INV}\nIV: {IV}")



# KEY_P1 = list(range(64))
# KEY_P2 = list(range(64))
# shuffle(KEY_P1)
# shuffle(KEY_P2)
# print(KEY_P1)
# print(KEY_P2)