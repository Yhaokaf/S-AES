from fun import encrypt,decrypt
from double_encrypt import double_encrypt,double_decrypt
def meet_in_the_middle_attack(plaintext, ciphertext):
    """
    使用中间相遇攻击找到双重加密的密钥 (K1 + K2)
    :param plaintext: 明文，16 位二进制字符串
    :param ciphertext: 密文，16 位二进制字符串
    :return: 找到的密钥组合 (K1, K2) 列表，或空列表如果没有找到
    """
    forward_map = {}
    found_keys = []

    # 前向加密：遍历所有可能的 K1
    for k1 in range(2**16):
        # 将 K1 转换为 16 位二进制字符串
        k1_bin = format(k1, '016b')
        # 使用 K1 对明文加密
        intermediate_cipher = encrypt(plaintext, k1_bin)
        # 记录加密结果及其对应的 K1
        forward_map[intermediate_cipher] = k1_bin

    # 反向解密：遍历所有可能的 K2
    for k2 in range(2**16):
        # 将 K2 转换为 16 位二进制字符串
        k2_bin = format(k2, '016b')
        # 使用 K2 对密文解密
        intermediate_plain = decrypt(ciphertext, k2_bin)
        # 检查解密结果是否在前向加密结果中
        if intermediate_plain in forward_map:
            # 如果找到匹配，则记录对应的 K1 和 K2
            found_keys.append((forward_map[intermediate_plain], k2_bin))

    return found_keys

if __name__ == '__main__':

    # 测试示例
    plaintext = "1010101010101010"  # 16 位明文
    ciphertext = double_encrypt(plaintext, "11001100110011001100110011001100")  # 使用双重加密获取密文
    print(f"已知明文: {plaintext}")
    print(f"已知密文: {ciphertext}")

    # 中间相遇攻击寻找密钥组合
    possible_keys = meet_in_the_middle_attack(plaintext, ciphertext)
    if possible_keys:
        print("找到的可能密钥组合 (K1, K2):")
        for k1, k2 in possible_keys[:3]:
            print(f"K1: {k1}, K2: {k2}")
    else:
        print("未找到密钥组合")
    print(possible_keys[0].__len__())
    print(possible_keys[0][1])
    k1 = possible_keys[0][0]
    k2 = possible_keys[0][1]
    print("进行加密测试：")
    print(double_encrypt(plaintext, str(k1) + str(k2)))
    print(ciphertext)

    print("进行解密测试：")
    print(double_decrypt(ciphertext, str(k1) + str(k2)))
    print(plaintext)