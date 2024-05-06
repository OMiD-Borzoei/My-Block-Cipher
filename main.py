KEY_SIZE = 192              # Must be Divisible by 3
BLOCK_SIZE = KEY_SIZE // 3 * 2
ROUNDS = 12

# If u change subkey_order, u have to change decrypt function too !!!!
SUBKEY_ORDER = [[0, 1, 2],  # LMR
                [0, 2, 1],  # LRM
                [1, 0, 2],  # MLR
                [1, 2, 0],  # MRL
                [2, 0, 1],  # RLM
                [2, 1, 0],  # RML
                ]


# Inverse of [0, 255] in GF(2^8) over 0x11B
S_BOX = [0, 1, 141, 246, 203, 82, 123, 209, 232, 79, 41, 192, 176, 225, 229, 199, 116, 180, 170, 75, 153, 43, 96, 95, 88, 63, 253, 204, 255, 64, 238, 178, 58, 110, 90,
         241, 85, 77, 168, 201, 193, 10, 152, 21, 48, 68, 162, 194, 44, 69, 146, 108, 243, 57, 102, 66, 242, 53, 32, 111, 119, 187, 89, 25, 29, 254, 55, 103, 45, 49, 245, 105, 167, 100, 171, 19, 84, 37, 233, 9, 237, 92, 5, 202, 76, 36, 135, 191, 24, 62, 34, 240, 81, 236, 97, 23, 22, 94, 175, 211, 73, 166, 54, 67, 244, 71, 145, 223, 51, 147, 33, 59, 121, 183, 151, 133, 16, 181, 186, 60, 182, 112, 208, 6, 161, 250, 129, 130, 131, 126, 127, 128, 150, 115, 190, 86, 155, 158, 149, 217, 247, 2, 185, 164, 222, 106, 50, 109, 216, 138, 132, 114, 42, 20, 159, 136, 249, 220, 137, 154, 251, 124, 46, 195, 143, 184, 101, 72, 38, 200, 18, 74, 206, 231, 210, 98, 12, 224, 31, 239, 17, 117, 120, 113, 165, 142, 118, 61, 189, 188, 134, 87, 11, 40, 47, 163, 218, 212, 228, 15, 169, 39, 83, 4, 27, 252, 172, 230, 122, 7, 174, 99, 197, 219, 226, 234, 148, 139, 196, 213, 157, 248, 144, 107, 177, 13, 214, 235, 198, 14, 207, 173, 8, 78, 215, 227, 93, 80, 30, 179, 91, 35, 56, 52, 104, 70, 3, 140, 221, 156, 125, 160, 205, 26, 65, 28]


KEY_P1 = [20, 61, 35, 33, 9, 24, 10, 18, 51, 22, 49, 44, 40, 63, 12, 16, 38, 0, 8, 45, 21, 13, 48, 1, 27, 2, 34, 58, 5, 53, 50,
          55, 25, 26, 54, 46, 4, 31, 30, 57, 37, 56, 15, 19, 32, 3, 23, 28, 29, 14, 39, 60, 6, 17, 52, 47, 7, 36, 43, 11, 42, 59, 41, 62]
KEY_P2 = [14, 43, 24, 17, 46, 28, 56, 33, 38, 41, 25, 5, 10, 11, 61, 3, 39, 22, 15, 62, 40, 34, 31, 51, 12, 30, 9, 63, 49, 23,
          19, 29, 21, 27, 45, 20, 50, 44, 0, 54, 36, 1, 7, 32, 52, 18, 60, 48, 57, 13, 42, 26, 8, 16, 53, 59, 37, 35, 47, 4, 2, 6, 58, 55]

F_P1 = [31, 24, 6, 34, 40, 44, 21, 25, 63, 22, 3, 43, 51, 62, 53, 7, 17, 2, 41, 13, 27, 28, 29, 23, 26, 54, 58, 18, 19, 4, 61, 50, 59, 36, 14, 12, 49, 8, 20, 46, 9, 0,
        32, 48, 16, 47, 55, 15, 5, 11, 52, 37, 45, 33, 10, 60, 39, 30, 1, 35, 56, 57, 42, 38]


def bin64(x: int) -> str:
    return bin(x)[2:].zfill(64)


def bin8(x: int) -> str:
    return bin(x)[2:].zfill(8)


def rotate_left(num, rotate_by, num_bits):
    # Perform left rotation
    return ((num << rotate_by) | (num >> (num_bits - rotate_by))) & ((1 << num_bits) - 1)


def divide_key(key: int) -> list[str]:
    key = bin(key)[2:].zfill(KEY_SIZE)
    left = key[:KEY_SIZE//3]
    middle = key[KEY_SIZE//3:KEY_SIZE//3*2]
    right = key[KEY_SIZE//3*2:]
    return left, middle, right


def f_function(sub_key: int, x: int) -> int:
    tmp = sub_key ^ x
    tmps = []
    for i in range(8):
        tmp >> 8*i
        tmps.append(tmp % 256)

    for i in range(len(tmps)):
        try:
            tmps[i] = S_BOX[rotate_left(tmps[i], i, 8)]
        except:
            print(rotate_left(tmps[i], i, 8), tmps[i], i, 32<<3, 32>>5, 32<<3 | 32>>5)
            exit(0)
        
    ret = 0
    for i in range(8):
        ret += tmps[i]*2**i

    return int(permute(bin64(ret), F_P1), 2)


def permute(x: str, permutation: list) -> str:
    ret = ''
    for i in permutation:
        ret += x[i]
    return ret


def sub_key_generator(key: int, round: int) -> int:
    if not 1 <= round <= ROUNDS:
        return None

    div_key = divide_key(key)
    order = SUBKEY_ORDER[(round-1) % 6]

    left, mid, right = [int(div_key[i], 2) for i in order]

    tmp = mid ^ right
    tmp = permute(bin64(tmp), KEY_P1)
    tmp = int(tmp, 2) ^ left
    tmp = permute(bin64(tmp), KEY_P2)

    return int(tmp, 2)  # P2(P1(M xor R) xor L)


def sub_keys_generator(key: int) -> list[int]:
    return [sub_key_generator(key, i) for i in range(1, ROUNDS+1)]


def encrypt(plain_text: str, key: int) -> str:

    sub_keys = sub_keys_generator(key)
    
    while (len(plain_text) % 16 != 0):
        plain_text += " "

    blocks, bytes = [], []

    for i in plain_text:
        bytes.append(bin8(ord(i)))

        if len(bytes) == 16:
            blocks.append('')
            for i in bytes:
                blocks[-1] += i
            bytes.clear()
    
    #print(blocks)
    
    
    cipher_blocks = []
    for block in blocks:
        cipher_blocks.append(encrypt_block(block, sub_keys))

    #print(cipher_blocks)

    cipher_text = ''
    for cblock in cipher_blocks:
        for i in range(16):
            byte = int(cblock[i*8:i*8+8], 2)    
            cipher_text += chr(byte)

    return cipher_text


def encrypt_block(block: str, sub_keys: list[int]) -> int:

    
    
    left, right = block[:BLOCK_SIZE//2], block[BLOCK_SIZE//2:]
    left, right = int(left, 2), int(right, 2)

    round = 1
    while round <= ROUNDS:
        
        print(round)
        print(bin64(right))
        print(bin64(left))
        print(bin64(sub_keys[round-1]), end='\n\n')
        
        next_left = f_function(sub_keys[round-1], right)

        right = next_left ^ left
        left = next_left

        round += 1

    return bin64(right) + bin64(left)


def decrypt(cipher_text: str, key: int) -> int:

    right, middle, left = divide_key(key)

    reversed_key = int(right + middle + left, 2)

    return encrypt(cipher_text, reversed_key)


if __name__ == "__main__":
    key = 51278469120581351
    plain = "OMID Re"
    cipher = encrypt(plain, key)
    print(cipher)
    # for i in cipher:
    #     print(ord(i), end=' ')
    # print()
    # dec = decrypt(cipher, key)
    # for i in dec:
    #     print(ord(i), end=' ')
