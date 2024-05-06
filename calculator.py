irreducible_polynomial: list = [8, 4, 3, 1, 0]  # x8+x4+x3+x1+x0


def polynomial_to_string(l: list) -> str:
    l, st = list(reversed(sorted(l))), ''
    for i in l:
        st += '1' if i == 0 else 'x' if i == 1 else f'X{i}'
        st += '+' if l.index(i) < len(l) - 1 else ''
    return st if st else '0'


def binary_to_polynomial(st: str) -> list:
    return [int(i) for i in range(len(st) - 1, -1, -1) if st[-1 * i - 1] == '1']


def hex_to_binary(st: str) -> str:
    return bin(int(st, 16))[2:]


def go_in_GF2(l: list) -> list:
    return sorted(set([i for i in l if l.count(i) % 2 != 0]), reverse=True)


def reduce(power: int, irreducible_poly: list) -> list:
    order, tmp = max(irreducible_poly), [0]
    reduce_with = [i for i in irreducible_poly if i != order]

    for i in range(power // order):
        tmp = multiply(reduce_with, tmp)
    # tmp is now equal to = reduce_with^(power//order)

    # we should return tmp * x^(power%order)
    return multiply(tmp, [power % order])


def multiply(a: list, b: list, irreducible_poly=irreducible_polynomial) -> list:
    mul, newMul, order = [], [], max(irreducible_poly)
    for i in a:
        mul.extend([(i + j) for j in b])

    for i in go_in_GF2(mul):  # Coefficients must be in GF(2)
        # Powers higher than order of irreducible_poly must be reduced
        newMul.extend(reduce(i, irreducible_poly) if i >= order else [i])

    return go_in_GF2(newMul)  # Again, Coefficients must be in GF(2)


def polynomial_to_int(poly: list) -> int:
    if poly == []:
        return 0
    l = [0]*(max(poly)+1)
    for i in poly:
        l[i] = 1
    st = ''
    for i in l[::-1]:
        st += str(i)
    return int(st, 2)

def polynomial_to_hex(poly: list) -> str:
    return hex(polynomial_to_int(poly))


def divide(p1: list, p2: list) -> list[list[int], list[int]]:
    rem, q = p1, []

    while polynomial_to_int(rem) >= polynomial_to_int(p2):
        
        q.append(max(rem) - max(p2))
        new_poly = [(q[-1]+i) for i in p2]
        rem = go_in_GF2(new_poly + rem)

    return rem, q


def inverse(poly:list[int], irreducible_poly=irreducible_polynomial) -> list:
    if poly == []:
        return []
    
    us = [[], [0]]
    rs = [irreducible_poly, poly]
    qs = []

    i = 2
    while rs[-1] != [0]:

        p1, p2 = rs[i-2], rs[i-1]
        rem, q = divide(p1, p2)
        rs.append(rem)
        qs.append(q)
        us.append(go_in_GF2(us[i-2] + multiply(us[i-1], q)))

        i += 1
    return us[-1]


def aes_s_box(x: int):
    x_poly = binary_to_polynomial(hex_to_binary(hex(x)))
    inv = inverse(x_poly)
    inv = int(polynomial_to_hex(inv), 16)
    
    shift = lambda x, num: (x << num) & 0xFF 
    
    return hex(inv ^ shift(inv, 1) ^ shift(inv, 2) ^ shift(inv, 3) ^ shift(inv, 4) ^ 0x63)

if __name__ == "__main__":

    while True:
        poly = input("Enter poly in Hex: ")
        poly = binary_to_polynomial((hex_to_binary(poly)))
        inv = inverse(poly)
        print('Inverse: ', polynomial_to_hex(inv))
    l = []
    for i in range(2**8):
        l.append(int(polynomial_to_hex(inverse(binary_to_polynomial(hex_to_binary(hex(i))))), 16))
    print(l)





