import random

# ------------------------- S-AES 算法实现 -------------------------

# S盒和逆S盒（使用4位二进制表示）
S_BOX = {
    '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
    '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
    '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
    '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111'
}
INV_S_BOX = {v: k for k, v in S_BOX.items()}

# 行移位
def shift_rows(s):
    return s[:4] + s[12:] + s[8:12] + s[4:8]

# 逆行移位
def inv_shift_rows(s):
    return s[:4] + s[12:] + s[8:12] + s[4:8]

# 有限域 GF(2^4) 乘法
def gf_mul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x10:
            a ^= 0b10011  # 使用多项式 x^4 + x + 1 进行约简
        b >>= 1
    return p & 0xF  # 保证结果在 4 位内

# 列混淆
def mix_columns(state):
    t0 = int(state[:4], 2)
    t2 = int(state[4:8], 2)
    t1 = int(state[8:12], 2)
    t3 = int(state[12:], 2)
    result = (
            (t0 ^ mul4(t2)) << 12 |
            (t2 ^ mul4(t0)) << 8 |
            (t1 ^ mul4(t3)) << 4 |
            (t3 ^ mul4(t1))
    )
    return bin(result)[2:].zfill(16)

# 逆列混淆操作
def inv_mix_columns(state):
    t0 = int(state[:4], 2)
    t2 = int(state[4:8], 2)
    t1 = int(state[8:12], 2)
    t3 = int(state[12:], 2)
    result = (
            (mul9(t0) ^ mul2(t2)) << 12 |
            (mul2(t0) ^ mul9(t2)) << 8 |
            (mul9(t1) ^ mul2(t3)) << 4 |
            (mul2(t1) ^ mul9(t3))
    )
    return bin(result)[2:].zfill(16)

# GF(2^4) 下乘法函数
def mul2(nibble):
    return ((nibble << 1) & 0xF) ^ 0x3 if (nibble & 0x8) else (nibble << 1) & 0xF

def mul4(nibble):
    return mul2(mul2(nibble)) & 0xF

def mul9(nibble):
    return (mul4(mul2(nibble)) ^ nibble) & 0xF

# 密钥扩展
def key_expansion(key):
    # RCON常量
    R_CON = ['10000000', '00110000']
    # 初始化 w0 和 w1
    w = [key[:8], key[8:]]

    # 定义 g 函数，包括 RotNib 和 SubNib 操作
    def g(word, rcon):
        # RotNib：将 word 的前4位和后4位对调
        rotated = word[4:] + word[:4]
        # SubNib：对调后的前4位和后4位分别通过 S_BOX 替换
        substituted = S_BOX[rotated[:4]] + S_BOX[rotated[4:]]
        # 将替换后的结果与 rcon 异或
        return bin(int(substituted, 2) ^ int(rcon, 2))[2:].zfill(8)

    # 生成 w2 和 w3
    w.append(bin(int(w[0], 2) ^ int(g(w[1], R_CON[0]), 2))[2:].zfill(8))  # w2 = w0 ⊕ g(w1)
    w.append(bin(int(w[2], 2) ^ int(w[1], 2))[2:].zfill(8))  # w3 = w2 ⊕ w1

    # 生成 w4 和 w5
    w.append(bin(int(w[2], 2) ^ int(g(w[3], R_CON[1]), 2))[2:].zfill(8))  # w4 = w2 ⊕ g(w3)
    w.append(bin(int(w[4], 2) ^ int(w[3], 2))[2:].zfill(8))  # w5 = w4 ⊕ w3
    return w

# 代换字节
def sub_nibbles(s):
    return ''.join([S_BOX[s[i:i + 4]] for i in range(0, 16, 4)])

# 逆代换字节
def inv_sub_nibbles(s):
    return ''.join([INV_S_BOX[s[i:i + 4]] for i in range(0, 16, 4)])

# 异或操作
def xor(a, b):
    return bin(int(a, 2) ^ int(b, 2))[2:].zfill(len(a))

# 加密函数
def encrypt(plaintext, key):
    keys = key_expansion(key)
    # 初始轮密钥加
    state = xor(plaintext, keys[0] + keys[1])  #
    # 第一轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)  # 第一轮列混淆
    state = xor(state, keys[2] + keys[3])
    # 第二轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    ciphertext = xor(state, keys[4] + keys[5])  # 第二轮没有列混淆
    return ciphertext

# 解密函数
def decrypt(ciphertext, key):
    keys = key_expansion(key)
    # 第二轮逆操作
    state = xor(ciphertext, keys[4] + keys[5])
    state = inv_shift_rows(state)
    state = inv_sub_nibbles(state)
    # 第一轮逆操作
    state = xor(state, keys[2] + keys[3])
    state = inv_mix_columns(state)  # 第一轮逆列混淆
    state = inv_shift_rows(state)
    state = inv_sub_nibbles(state)
    plaintext = xor(state, keys[0] + keys[1])
    return plaintext

# 输入验证函数
def validate_binary_input(input_str, length):
    if len(input_str) != length:
        return False
    return all(c in '01' for c in input_str)

# ------------------------- CBC 模式实现 -------------------------

def pad_binary_string(s, block_size=16):
    padding_length = (block_size - len(s) % block_size) % block_size
    return s + '0' * padding_length

def split_blocks(s, block_size=16):
    return [s[i:i + block_size] for i in range(0, len(s), block_size)]

def generate_iv(block_size=16):
    return ''.join(random.choice('01') for _ in range(block_size))

def encrypt_cbc(plaintext, key, iv):
    keys = key_expansion(key)
    plaintext = pad_binary_string(plaintext)
    blocks = split_blocks(plaintext)
    ciphertext_blocks = []
    previous = iv
    for block in blocks:
        block_xor = xor(block, previous)
        encrypted = encrypt(block_xor, key)
        ciphertext_blocks.append(encrypted)
        previous = encrypted
    return ''.join(ciphertext_blocks)
#
# def decrypt_cbc(ciphertext, key, iv):
#     keys = key_expansion(key)
#     blocks = split_blocks(ciphertext)
#     plaintext_blocks = []
#     previous = iv
#     for block in blocks:
#         decrypted = decrypt(block, key)
#         plaintext = xor(decrypted, previous)
#         plaintext_blocks.append(plaintext)
#         previous = block
#     return ''.join(plaintext_blocks).rstrip('0')  # 去除填充

def decrypt_cbc(ciphertext, key, iv):
    keys = key_expansion(key)
    blocks = split_blocks(ciphertext)
    plaintext_blocks = []
    previous = iv
    for block in blocks:
        decrypted = decrypt(block, key)
        plaintext = xor(decrypted, previous)
        plaintext_blocks.append(plaintext)
        previous = block
    return ''.join(plaintext_blocks)  # 不去除任何填充


def tamper_ciphertext(ciphertext, tamper_at=16):
    # 将第 tamper_at 位进行翻转
    if tamper_at < 0 or tamper_at >= len(ciphertext):
        print("Tamper position out of range.")
        return ciphertext
    tampered = list(ciphertext)
    tampered[tamper_at] = '1' if ciphertext[tamper_at] == '0' else '0'
    return ''.join(tampered)

# ------------------------- 测试主函数 -------------------------

def main():
    # 示例明文（大于16位的二进制字符串）
    plaintext = "1101010110110010101010101111000011010101101100101010101011110000"  # 32位
    # 确保明文是二进制且长度为任意长度
    if not all(c in '01' for c in plaintext):
        print("明文必须是二进制字符串。")
        return

    # 密钥（16位）
    key = "1010101010110010"  # 需要填充到16位
    key = pad_binary_string(key, 16)
    if not validate_binary_input(key, 16):
        print("密钥必须是16位的二进制字符串。")
        return

    # 生成初始向量（IV）
    iv = generate_iv(16)
    print(f"初始向量 (IV): {iv}")

    # CBC 加密
    ciphertext = encrypt_cbc(plaintext, key, iv)
    print(f"密文: {ciphertext}")

    # CBC 解密
    decrypted = decrypt_cbc(ciphertext, key, iv)
    print(f"解密后的明文: {decrypted}")

    # 篡改密文
    tampered_ciphertext = tamper_ciphertext(ciphertext, tamper_at=16)  # 篡改第17位（索引16）
    print(f"篡改后的密文: {tampered_ciphertext}")

    # 解密篡改后的密文
    decrypted_tampered = decrypt_cbc(tampered_ciphertext, key, iv)
    print(f"解密篡改后的密文得到的明文: {decrypted_tampered}")

    # 比较原始明文和解密后的明文
    print("\n对比:")
    print(f"原始明文:    {plaintext}")
    print(f"解密明文:    {decrypted}")
    print(f"篡改后 解密 : {decrypted_tampered}")

if __name__ == "__main__":
    main()
