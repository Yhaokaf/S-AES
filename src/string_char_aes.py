from fun import encrypt, decrypt



def encrypt_ascii_string(input_str, key):
    """
    :param input_str:输入字符串 （待加密字符串）
    :param key: 密钥  单字符 或  16bit密钥
    :return: 加密的结果 单字符
    """
    # 判断是否为 16 位二进制字符串
    if isinstance(key, str) and len(key) == 16 and all(char in '01' for char in key):
        result = encrypt(format(ord(input_str), '016b'), key)
        return chr(int(result, 2))
    elif isinstance(key, str) and len(key) == 1 and ord(key) < 128:
        result=encrypt(format(ord(input_str), '016b'), format(ord(key), '016b'))
        return chr(int(result, 2))


def decrypt_ascii_string(input_str, key):
    """
    :param input_str:输入字符串 （待解密 单字符）
    :param key: 密钥  单字符 或  16bit密钥
    :return: 解密的结果 单字符
    """
    # 判断是否为 16 位二进制字符串
    if isinstance(key, str) and len(key) == 16 and all(char in '01' for char in key):
        result = decrypt(format(ord(input_str), '016b'), key)
        return chr(int(result, 2))
    elif isinstance(key, str) and len(key) == 1 and ord(key) < 128:
        result=decrypt(format(ord(input_str), '016b'), format(ord(key), '016b'))
        return chr(int(result, 2))




def encrypt_string(input_str, key):
    """
    对整个字符串进行加密
    :param input_str: 待加密的字符串
    :param key: 密钥（单字符或16位二进制字符串）
    :return: 加密后的字符串
    """
    encrypted_str = ""
    for char in input_str:
        encrypted_char = encrypt_ascii_string(char, key)
        if encrypted_char is False:
            raise ValueError("Invalid key format. Key must be a single ASCII character or a 16-bit binary string.")
        encrypted_str += encrypted_char
    return encrypted_str

def decrypt_string(encrypted_str, key):
    """
    对整个字符串进行解密
    :param encrypted_str: 加密后的字符串
    :param key: 密钥（单字符或16位二进制字符串）
    :return: 解密后的字符串
    """
    decrypted_str = ""
    for char in encrypted_str:
        decrypted_char = decrypt_ascii_string(char, key)
        if decrypted_char is False:
            raise ValueError("Invalid key format. Key must be a single ASCII character or a 16-bit binary string.")
        decrypted_str += decrypted_char
    return decrypted_str


if __name__ == '__main__':
    # print("加密")
    # print(encrypt_ascii_string("A",format(12, '016b')))
    # print("解密")
    # print(decrypt_ascii_string(encrypt_ascii_string("A",format(12, '016b')), format(12, '016b')))
    # print("加密")
    # print(encrypt_ascii_string("a",2312))
    # print("解密")
    # print(decrypt_ascii_string(encrypt_ascii_string("A",format(12, '016b')), format(12, '016b')))
    original_text = "hello"
    key = "Ka"  # 可以是单个 ASCII 字符或者 16 位二进制密钥

    # 加密
    encrypted_text = encrypt_string(original_text, key)
    print(f"加密后的文本: {encrypted_text}")
    print(f"解密后：{decrypt_string(encrypted_text, key)}")