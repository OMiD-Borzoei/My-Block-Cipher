from numpy import genfromtxt

# You Can set these Parameters to anything u want, but u must follow some rules

# For faster encryption -> lower the number of rounds, but keep in mind, the less rounds u have
# the less secure ur encryption is.

# For better Security, Increase key size and block size, however, keep in mind it slows down the process.

BLOCK_SIZE = 256  # in bits, Must be dividable by 8
KEY_SIZE = 128    # Must be half of BLOCK_SIZE
# If u change any one of the constants above, u must run get_permutation.py once before running this script
ROUNDS = 16       # Must be Less than KEY_SIZE

AES_S_BOX = genfromtxt('aes_s_box.txt', dtype='str')

IP = genfromtxt('IP.txt', dtype='int')
KP = genfromtxt('KP.txt', dtype='int')
FP = genfromtxt('FP.txt', dtype='int')
IP_INV = genfromtxt('IP_INV.txt', dtype='int')

KEY = ''.join(genfromtxt('KEY.txt', dtype='str').tolist())
IV = ''.join(genfromtxt('IV.txt', dtype='str').tolist())


# ---- Here are some methods which we'll use a lot further down the road -----
def rotate_right(binary_str, n):
    # Ensure n is within the length of the binary string
    n = n % len(binary_str)
    return binary_str[-n:] + binary_str[:-n]


def b2h(x: str, len=BLOCK_SIZE//4) -> str:
    return hex(int(x, 2))[2:].zfill(len)


def h2b(x: str, len=BLOCK_SIZE) -> str:
    return bin(int(x, 16))[2:].zfill(len)


def xor(x: str, y: str, is_hex=False) -> str:
    if is_hex:
        x, y = h2b(x), h2b(y)
    ret = ''
    for i in range(len(x)):
        if x[i] == y[i]:
            ret += '0'

        else:
            ret += '1'
    return b2h(ret) if is_hex else ret


# Inputs 1 byte Binary and Outputs 1 byte Binary:
def s_box(x: str) -> str:
    if len(x) != 8:
        raise ValueError("Input of S_Box must be 1 byte long")

    row, col = int(x[:4], 2), int(x[4:], 2)
    return h2b(AES_S_BOX[row][col], 8)


def permute(x: str, permutation: list) -> str:
    ret = ''
    for i in permutation:
        ret += x[i]
    return ret


def sub_key_generator(key: str) -> list[str]:
    if len(key) < len(KP):
        key = h2b(key, KEY_SIZE*4)

    # Permute Key:
    key = permute(key, KP)

    rot_num = KEY_SIZE//ROUNDS
    subs, counter = [], '1'*rot_num

    for _ in range(ROUNDS):
        key = rotate_right(key, rot_num)
        subs.append(xor(key, counter.zfill(len(key))))
        counter += '1'*rot_num

    return subs


def f(r: str, sub_key: str):
    # Split inputs into n different bytes:
    rs = [r[i:i+8] for i in range(0, len(r), 8)]
    subs = [sub_key[i:i+8] for i in range(0, len(sub_key), 8)]

    fs = []
    for i in range(len(rs)):
        fs.append(s_box(xor(s_box(rs[i]), s_box(subs[i]))))

    return permute(''.join(fs), FP)


def feistel(l: str, r: str, key: str) -> str:
    new_r = xor(l, f(r, key))
    return r, new_r


def encrypt(plain_text: str, decrypt=False, inp_binary=False, mode='ECB', parallel = False) -> str:

    supported_modes = ['CBC', 'OFB', 'CTR', 'ECB']
    if mode not in supported_modes:
        raise ValueError(f'Valid Values for mode are: {supported_modes}')

    # __Part1 --> Change Plain_text form to Hex__

    # If Input is Binary, Change it to Hex:
    if inp_binary:
        inp_len = len(plain_text)
        hex_plain_text = hex(int(plain_text, 2))[2:].zfill(inp_len//4)
    else:
        # If We Are In Encypt Mode encode, English Message to Hex:
        if not decrypt:
            hex_plain_text = plain_text.encode().hex()
        # If We Are Decrypting We Don't need to change Cipher to Hex because it already is Hex
        else:
            hex_plain_text = plain_text

# __Part2 --> Split Message to Different Blocks__
    blocks = [hex_plain_text[i:i+BLOCK_SIZE//4]
              for i in range(0, len(hex_plain_text), BLOCK_SIZE//4)]

    # Ensure that last block hast the same size than others:
    while len(blocks[-1]) < BLOCK_SIZE//4:
        blocks[-1] += '0'


# __Part3 --> Generate SubKeys __

    # If we are in Decrpyt mode we need to reverse sub_keys !!
    sub_keys = sub_key_generator(KEY)
    sub_keys = sub_keys[::-1] if decrypt else sub_keys


# __Part4 --> Encrpyt Each Block

    if mode == 'ECB':
        if not parallel:
            cipher_text = [encrypt_block(i, sub_keys) for i in blocks]
            cipher_text = ''.join(cipher_text)
        
        if parallel:
            pass 

    elif mode == 'CBC':

        # Encrypting in CBC mode:
        if not decrypt:

            cipher_text, last_encrypted_block = '', IV
            for block in blocks:
                last_encrypted_block = encrypt_block(
                    xor(block, last_encrypted_block, True), sub_keys)
                cipher_text += last_encrypted_block

        # Decrypting in CBC mode:
        else:

            # Sequential Decyrpting:
            if not parallel:
                cipher_text = xor(encrypt_block(blocks[0], sub_keys), IV, True)
                for i in range(1, len(blocks)):
                    cipher_text += xor(encrypt_block(blocks[i],
                                    sub_keys), blocks[i-1], True)
            # Parallel Decrypting:
            else:
                """Your Job"""
                pass 
            
    elif mode == 'CTR':
        """Your Job"""
        pass 
    
    elif mode == 'OFB':
        """Your Job"""
        pass 

    return bytes.fromhex(cipher_text).decode() if decrypt else cipher_text


def encrypt_block(inp: str, sub_keys: list[str]) -> str:

    # Change to Binary:
    inp = h2b(inp)
    # Perform Initial Permutaion:
    inp = permute(inp, IP)

    # Continue to Feistel Network:
    left, right = inp[:BLOCK_SIZE//2], inp[BLOCK_SIZE//2:]

    for i in range(ROUNDS):
        left, right = feistel(left, right, sub_keys[i])

    # Swap l and r and Perform Final Permutaion:
    out = permute(right+left, IP_INV)

    return format(int(out, 2), f'0{BLOCK_SIZE//4}x')


if __name__ == "__main__":
    mode = 'ECB'  

    plain_text = "6 Nuclear Missiles will be launched at 5:32 AM October 7, 2024 "
    # plain_text = "I ♡ Cyper Security"
    # plain_text = "This is the Plain Text"
    # plain_text = "Coded By Omid Reza Borzoei 99243020"
    # plain_text = "You Can See a Variety of Characters In this Message: @#$%^&*()!~+:?><[]\|"
    cipher_text = encrypt(plain_text, mode=mode)
    decrypted_text = encrypt(cipher_text, decrypt=True, mode=mode)

    print(f"Plain Text        :\t{plain_text}")

    print(f"Key               :\t0x{KEY.upper()}")
    print(f"Mode              :\t{mode}\n")
    if mode != 'normal':
        print(f"IV                :\t0x{IV.upper()}\n")
    print(f"Cipher Text       :\t{cipher_text}\n")
    print(f"Decrypted         :\t{decrypted_text}")