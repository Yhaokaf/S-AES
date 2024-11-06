from fun import encrypt, decrypt
def triple_encrypt(plaintext, key_48bit):
    """
    使用三重加密对 16-bit 明文进行加密，密钥长度为 48 位。
    :param plaintext: 16 位二进制字符串
    :param key_48bit: 48 位二进制字符串，分为三个 16 位密钥
    :return: 加密后的密文
    """
    # 验证输入格式
    # if not validate_binary_input(plaintext, 16) or not validate_binary_input(key_48bit, 48):
    #     raise ValueError("Plaintext must be 16-bit and key must be 48-bit binary strings.")

    # 将48位密钥分成三个16位密钥
    key1 = key_48bit[:16]
    key2 = key_48bit[16:32]
    key3 = key_48bit[32:]

    # 第一次加密
    intermediate1 = encrypt(plaintext, key1)
    # 第二次加密
    intermediate2 = encrypt(intermediate1, key2)
    # 第三次加密
    final_ciphertext = encrypt(intermediate2, key3)

    return final_ciphertext


def triple_decrypt(ciphertext, key_48bit):
    """
    使用三重解密对 16-bit 密文进行解密，密钥长度为 48 位。
    :param ciphertext: 16 位二进制字符串
    :param key_48bit: 48 位二进制字符串，分为三个 16 位密钥
    :return: 解密后的明文
    """
    # # 验证输入格式
    # if not validate_binary_input(ciphertext, 16) or not validate_binary_input(key_48bit, 48):
    #     raise ValueError("Ciphertext must be 16-bit and key must be 48-bit binary strings.")

    # 将48位密钥分成三个16位密钥
    key1 = key_48bit[:16]
    key2 = key_48bit[16:32]
    key3 = key_48bit[32:]

    # 第一次解密
    intermediate1 = decrypt(ciphertext, key3)
    # 第二次解密
    intermediate2 = decrypt(intermediate1, key2)
    # 第三次解密
    final_plaintext = decrypt(intermediate2, key1)

    return final_plaintext

if __name__ == '__main__':
    # 测试示例
    plaintext = "1010101010101010"  # 16 位明文
    key_48bit = "110011001100110011001100110011001100110011001100"  # 48 位密钥

    # 三重加密
    ciphertext = triple_encrypt(plaintext, key_48bit)
    print(f"三重加密结果: {ciphertext}")

    # 三重解密
    decrypted_plaintext = triple_decrypt(ciphertext, key_48bit)
    print(f"三重解密结果: {decrypted_plaintext}")


