from random import shuffle, choice, randint
from calculator import aes_s_box

KEY = '11010001'
KEY_SIZE = 8
BLOCK_SIZE = 16  # in bits
ROUNDS = 12




IP = [0, 12, 14, 13, 7, 5, 6, 11, 9, 4, 10, 1, 3, 2, 15, 8]
IP_INV = [0, 11, 13, 12, 9, 5, 6, 4, 15, 8, 10, 7, 1, 3, 2, 14]
IV = "486e"


def xor(x: str, y: str) -> str:
    ret = ''
    for i in range(len(x)):
        if x[i] == y[i]:
            ret += '0'
        else:
            ret += '1'
    return ret


def b2h(x: str, len = BLOCK_SIZE//4) -> str:
    return hex(int(x, 2))[2:].zfill(len)

def h2b(x: str, len=BLOCK_SIZE) -> str:
    return bin(int(x, 16))[2:].zfill(len)


# Inputs 1 byte Binary and Outputs 1 byte Binary:
def s_box(x: str) -> str:
    if len(x) != 8:
        raise ValueError("Input of S_Box must be 1 byte long")

    return bin(int(aes_s_box(int(x, 2)), 16))[2:].zfill(8)


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
    return s_box(xor(s_box(r), s_box(sub_key)))


def feistel(l: str, r: str, key: str) -> str:
    new_r = xor(l, f(key, r))
    return r, new_r


def encrypt(plain_text: str, decrypt=False, inp_binary=False, mode='normal') -> str:
    global IV
    # __Part1 --> Changit Plain_text form to Hex__

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

    parts = len(hex_plain_text)*4 // BLOCK_SIZE
    part_size = len(hex_plain_text)//parts
    blocks = [hex_plain_text[i:i+part_size]
              for i in range(0, len(hex_plain_text), part_size)]

    # Ensure that last block hast the same size than others:
    while len(blocks[-1]) < BLOCK_SIZE//4:
        blocks[-1] += '0'


# __Part3 --> Generate SubKeys __

    # If we are in Decrpyt mode we need to reverse sub_keys !!
    sub_keys = sub_key_generator(KEY)
    sub_keys = sub_keys[::-1] if decrypt else sub_keys


# __Part4 --> Encrpyt Each Block

    if mode == 'normal':
        cipher_text = [encrypt_block(i, sub_keys) for i in blocks]
        cipher_text = ''.join(cipher_text)

    elif mode == 'CBC':

        if not decrypt:
            cipher_text, last_encrypted_block = '', IV

            for block in blocks:

                block = bin(int(block, 16))[2:].zfill(BLOCK_SIZE)
                last_encrypted_block = bin(int(last_encrypted_block, 16))[
                    2:].zfill(BLOCK_SIZE)
                xorr = hex(int(xor(block, last_encrypted_block), 2))[
                    2:].zfill(BLOCK_SIZE//4)

                last_encrypted_block = encrypt_block(xorr, sub_keys)
                cipher_text += last_encrypted_block

        else:
            bin_IV = bin(int(IV, 16))[2:].zfill(BLOCK_SIZE)

            first_decrypted_block = encrypt_block(blocks[0], sub_keys)

            first_decrypted_block = bin(int(first_decrypted_block, 16))[
                2:].zfill(BLOCK_SIZE)

            cipher_text = hex(int(xor(first_decrypted_block, bin_IV), 2))[
                2:].zfill(BLOCK_SIZE//4)

            for i in range(1, len(blocks)):
                decrypted = encrypt_block(blocks[i], sub_keys)
                decrypted = bin(int(decrypted, 16))[2:].zfill(BLOCK_SIZE)

                prev = bin(int(blocks[i-1], 16))[2:].zfill(BLOCK_SIZE)

                cipher_text += hex(int(xor(decrypted, prev), 2)
                                   )[2:].zfill(BLOCK_SIZE//4)

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


def diffusion_checker(plain_text_length: int = 256, mode='normal'):

    pl = [choice(('0', '1')) for _ in range(plain_text_length)]
    c1 = encrypt(''.join(pl), inp_binary=True, mode=mode)

    pl2 = pl[::]
    idx = randint(0, plain_text_length-1)
    pl2[idx] = '0' if pl2[idx] == '1' else '1'

    c2 = encrypt(''.join(pl2), inp_binary=True, mode=mode)

    c1, c2 = bin(int(c1, 16)), bin(int(c2, 16))

    pl_diff = 0
    for i in range(len(pl)):
        if pl[i] != pl2[i]:
            pl_diff += 1

    diff = 0
    for i in range(len(c1)):
        if c1[i] != c2[i]:
            diff += 1

    print(f"{pl_diff} bit(s) changed in plain text")
    print(f"{diff} bit(s) changed in cipher")


if __name__ == "__main__":
    # b = '10011010'
    # print(IP)
    # print(permute(b, IP))
    # print(IP_INV)
    # print(permute(permute(b, IP), IP_INV))

    print("Avalanche Effect: ")
    diffusion_checker(mode='CBC')
    print("\n\n")

    plain_text = "Nuclear Weapons will be launched at 5:32 AM October 7, 2024 "
    print(f"Plain Text        :\t{plain_text}")

    print(f"Encoded Plain Text:\t{plain_text.encode().hex()}\n")

    print(f"Key = {hex(int(KEY, 2))}")
    cipher_text = encrypt(plain_text, mode='CBC')
    print(f"Cipher Text       :\t{cipher_text}\n")

    decrypted_text = encrypt(cipher_text, decrypt=True, mode='CBC')
    print(f"Decrypted         :\t{decrypted_text}")

    # print(format(int("00000110", 2), '02x'))
