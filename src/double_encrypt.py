from fun import decrypt,encrypt



def double_encrypt(plaintext, key_32bit):
    """
    使用双重加密对 16-bit 明文进行加密，密钥长度为 32 位。
    :param plaintext: 16 位二进制字符串
    :param key_32bit: 32 位二进制字符串，分为两个 16 位密钥
    :return: 加密后的密文
    """

    # 将32位密钥分成两个16位密钥
    key1 = key_32bit[:16]
    key2 = key_32bit[16:]

    # 第一次加密
    intermediate_cipher = encrypt(plaintext, key1)

    # 第二次加密
    final_ciphertext = encrypt(intermediate_cipher, key2)

    return final_ciphertext


def double_decrypt(ciphertext, key_32bit):
    """
    使用双重解密对 16-bit 密文进行解密，密钥长度为 32 位。
    :param ciphertext: 16 位二进制字符串
    :param key_32bit: 32 位二进制字符串，分为两个 16 位密钥
    :return: 解密后的明文
    """

    # 将32位密钥分成两个16位密钥
    key1 = key_32bit[:16]
    key2 = key_32bit[16:]

    # 第一次解密
    intermediate_plain = decrypt(ciphertext, key2)

    # 第二次解密
    final_plaintext = decrypt(intermediate_plain, key1)

    return final_plaintext

if __name__ == '__main__':
    # 测试示例
    plaintext = "1010101010101010"  # 16-bit 明文
    key_32bit = "11001100110011001100110011001100"  # 32-bit 密钥

    # 双重加密
    ciphertext = double_encrypt(plaintext, key_32bit)
    print(f"双重加密结果: {ciphertext}")

    # 双重解密
    decrypted_plaintext = double_decrypt(ciphertext, key_32bit)
    print(f"双重解密结果: {decrypted_plaintext}")


