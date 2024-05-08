from random import choice, randint
from main import encrypt


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
        try:
            if c1[i] != c2[i]:
                diff += 1
        except:
            diff += 1

    print(f"plain_text_length = {plain_text_length}")
    print(f"bit at poisition {idx} changed in plain text")
    print(f"{diff} bit(s) changed in cipher")
    return diff


if __name__ == "__main__":
    diffusion_checker()
