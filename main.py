KEY_SIZE = 192              # Must be Divisible by 3
BLOCK_SIZE = KEY_SIZE // 3
ROUNDS = 12

# If u change subkey_order, u have to change decrypt function too !!!!
SUBKEY_ORDER = [[0, 1, 2],  # LMR
                [0, 2, 1],  # LRM
                [1, 0, 2],  # MLR
                [1, 2, 0],  # MRL
                [2, 0, 1],  # RLM
                [2, 1, 0],  # RML
                ]



KEY_P1 = [20, 61, 35, 33, 9, 24, 10, 18, 51, 22, 49, 44, 40, 63, 12, 16, 38, 0, 8, 45, 21, 13, 48, 1, 27, 2, 34, 58, 5, 53, 50,
          55, 25, 26, 54, 46, 4, 31, 30, 57, 37, 56, 15, 19, 32, 3, 23, 28, 29, 14, 39, 60, 6, 17, 52, 47, 7, 36, 43, 11, 42, 59, 41, 62]
KEY_P2 = [14, 43, 24, 17, 46, 28, 56, 33, 38, 41, 25, 5, 10, 11, 61, 3, 39, 22, 15, 62, 40, 34, 31, 51, 12, 30, 9, 63, 49, 23,
          19, 29, 21, 27, 45, 20, 50, 44, 0, 54, 36, 1, 7, 32, 52, 18, 60, 48, 57, 13, 42, 26, 8, 16, 53, 59, 37, 35, 47, 4, 2, 6, 58, 55]




def divide_key(key: int) -> list[str]:
    left = slice_binary(key, end=KEY_SIZE//3)
    middle = slice_binary(key, start=KEY_SIZE//3, end=KEY_SIZE//3*2)
    right = slice_binary(key, start=KEY_SIZE//3*2)
    return left, middle, right


def f_function(sub_key: int, input: int) -> int:
    pass


def sub_key_generator(key: int, round: int) -> int:
    if not 1 <= round <= ROUNDS:
        return None

    div_key = divide_key(key)
    order = SUBKEY_ORDER[(round-1) % 6]

    new_key = ''
    for i in order:
        new_key += div_key[i]


def sub_keys_generator(key: int) -> list[int]:
    pass


def encrypt(plain_text: int, key: int) -> int:
    pass


def encrypt_block(block: int, key: int) -> int:
    pass


def decrypt(cipher_text: int, key: int) -> int:

    right, middle, left = divide_key(key)

    reversed_key = int(right + middle + left, 2)

    return encrypt(cipher_text, reversed_key)


# binaries are saved in int class which is not slicable,
# the function below helps us slide binaries by changing their type to str
def slice_binary(x: int, start: int = 0, end: int = None) -> str:
    return bin(x)[(2+start) if start is not None else 2: (2+end) if end is not None else None]



if __name__ == "__main__":
    
    
    pass 