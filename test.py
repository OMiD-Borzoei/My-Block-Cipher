from random import shuffle


def rem(x: str) -> str:
    if x[1] == 'x':
        return x[2:]
    else:
        return x


def xor(x: str, y: str) -> str:
    ret = ''
    for i in range(len(x)):
        if x[i] == y[i]:
            ret += '0'
        else:
            ret += '1'
    return ret


def andd(x: str, y: str) -> str:
    ret = ''
    for i in range(len(x)):
        if x[i] == y[i] and x[i] == '1':
            ret += '1'
        else:
            ret += '0'
    return ret


def orr(x: str, y: str) -> str:
    ret = ''
    for i in range(len(x)):
        if x[i] == '1' or y[i] == '1':
            ret += '1'
        else:
            ret += '0'
    return ret


KEY = '1011'
KEY_SIZE = 4
BLOCK_SIZE = 8  # in bits
ROUNDS = 2


IP = list(range(BLOCK_SIZE))
shuffle(IP)

IP_INV = [0]*BLOCK_SIZE
for i in range(BLOCK_SIZE):
    IP_INV[IP[i]] = i

# IP = [4, 1, 7, 5, 2, 3, 0, 6]
# IP_INV = [6, 1, 4, 5, 0, 3, 7, 2]


def permute(x: str, permutation: list) -> str:
    ret = ''
    for i in permutation:
        ret += x[i]
    return ret


def sub_key_generator(key: str):
    subs = []
    for i in range(ROUNDS):
        subs.append(xor(key, bin(i)[2:].zfill(len(key))))
    return subs


def f(r: str, sub_key: str):
    return xor(r, sub_key)


def feistel(l: str, r: str, key: str) -> str:
    new_r = xor(l, f(key, r))
    return r, new_r


def encrypt(plain_text: str, decrypt=False) -> str:

    length = len(plain_text)
    length *= 8
    mod = length % BLOCK_SIZE
    extra = BLOCK_SIZE - mod - 1
    extra //= 8
    plain_text += ' ' * extra

    if not decrypt:
        hex_plain_text = plain_text.encode().hex()
    else:
        hex_plain_text = plain_text

    parts = len(hex_plain_text)*4 // BLOCK_SIZE
    part_size = len(hex_plain_text)//parts

    blocks = [hex_plain_text[i:i+part_size]
              for i in range(0, len(hex_plain_text), part_size)]

    cipher_text = ''

    sub_keys = sub_key_generator(KEY)

    sub_keys = sub_keys[::-1] if decrypt else sub_keys

    for i in blocks:
        # print(i, encrypt_block(i, sub_keys))
        cipher_text += encrypt_block(i, sub_keys)

    return bytes.fromhex(cipher_text).decode() if decrypt else cipher_text


def encrypt_block(inp: str, sub_keys: list[str]) -> str:

    # Change to Binary:
    inp = bin(int(inp, 16))[2:].zfill(len(inp)*4)

    # Perform Initial Permutaion:
    inp = permute(inp, IP)

    # Continue to Feistel Network:
    l, r = inp[:BLOCK_SIZE//2], inp[BLOCK_SIZE//2:]

    for i in range(ROUNDS):
        l, r = feistel(l, r, sub_keys[i])

    # Swap l and r and Perform Final Permutaion:
    out = permute(r+l, IP_INV)

    return format(int(out, 2), f'0{BLOCK_SIZE//4}x')

    # return hex(int(r, 2))[2:]+hex(int(l, 2))[2:]


if __name__ == "__main__":

    # b = '10011010'
    # print(IP)
    # print(permute(b, IP))
    # print(IP_INV)
    # print(permute(permute(b, IP), IP_INV))

    plain_text = "Omid Reza Is Here MotherFuckers !!"
    print(f"Plain Text:\t{plain_text}")

    cipher_text = encrypt(plain_text)
    print(f"Cipher    :\t{cipher_text}")

    decrypted_text = encrypt(cipher_text, decrypt=True)
    print(f"Decrypted :\t{decrypted_text}")

    # print(format(int("00000110", 2), '02x'))
