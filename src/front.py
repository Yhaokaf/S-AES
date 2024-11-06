import streamlit as st
from fun import encrypt, decrypt
from double_encrypt import double_encrypt, double_decrypt
from double_meet import meet_in_the_middle_attack
from triple_encrypt import triple_encrypt, triple_decrypt
from cbc_all import encrypt_cbc, decrypt_cbc, tamper_ciphertext, generate_iv
from string_char_aes import encrypt_ascii_string, decrypt_ascii_string, encrypt_string, decrypt_string

# 设置页面配置
st.set_page_config(page_title="🔐 S-AES 加密工具", layout="wide", page_icon="🔒")

# 页面标题和描述
st.title("🔐 S-AES 加密工具")
st.markdown("""
一个功能强大的加解密工具，支持：
- 单字符与字符串加解密
- 双重与三重加密解密
- CBC 模式加解密
- 中间相遇攻击模拟
""")

# 使用漂亮的主题分隔线
st.markdown("---")

# 创建标签页
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔢 16位二进制加解密",
    "📝 字符串加解密",
    "🔐 双重加密/解密",
    "🔑 三重加密/解密",
    "🔒 CBC 模式加解密"
])

# Tab 1: 16位二进制加解密
with tab1:
    st.header("🔢 16位二进制加密/解密")
    st.markdown("输入16位二进制字符串和密钥进行加密或解密。")

    col1, col2 = st.columns(2)
    with col1:
        input_binary = st.text_input("📥 输入16位二进制字符串：", value="", max_chars=16, key="input_binary_tab1")
    with col2:
        key_binary = st.text_input("🔑 输入16位二进制密钥：", value="", max_chars=16, key="key_binary_tab1")

    # 验证函数
    def validate_binary_input(input_str, length):
        return len(input_str) == length and all(c in '01' for c in input_str)

    # 按钮布局
    col3, col4 = st.columns(2)
    with col3:
        if st.button("🔒 加密", key="encrypt_binary_tab1"):
            if validate_binary_input(input_binary, 16) and validate_binary_input(key_binary, 16):
                encrypted_binary = encrypt(input_binary, key_binary)
                st.success(f"✅ 加密结果：`{encrypted_binary}`")
            else:
                st.error("⚠️ 请输入有效的16位二进制明文和16位二进制密钥。")
    with col4:
        if st.button("🔓 解密", key="decrypt_binary_tab1"):
            if validate_binary_input(input_binary, 16) and validate_binary_input(key_binary, 16):
                decrypted_binary = decrypt(input_binary, key_binary)
                st.success(f"✅ 解密结果：`{decrypted_binary}`")
            else:
                st.error("⚠️ 请输入有效的16位二进制密文和16位二进制密钥。")

# Tab 2: 字符串加解密
with tab2:
    st.header("📝 字符串加密/解密")
    st.markdown("输入任意字符串和密钥进行加密或解密。密钥可以是单字符或16位二进制。")

    col1, col2 = st.columns(2)
    with col1:
        input_text = st.text_input("📥 输入字符串：", value="", key="input_text")
    with col2:
        key_str = st.text_input("🔑 输入密钥（单字符或16位二进制）：", value="", key="key_str")

    col3, col4 = st.columns(2)
    with col3:
        if st.button("🔒 加密字符串", key="encrypt_string"):
            if key_str:
                encrypted_text = encrypt_string(input_text, key_str)
                st.success(f"✅ 加密结果：`{encrypted_text}`")
            else:
                st.error("⚠️ 请提供有效的密钥。")
    with col4:
        if st.button("🔓 解密字符串", key="decrypt_string"):
            if key_str:
                decrypted_text = decrypt_string(input_text, key_str)
                st.success(f"✅ 解密结果：`{decrypted_text}`")
            else:
                st.error("⚠️ 请提供有效的密钥。")

# Tab 3: 双重加密/解密
with tab3:
    st.header("🔐 双重加密/解密")
    st.markdown("进行双重加密和解密，并模拟中间相遇攻击。")

    col1, col2 = st.columns(2)
    with col1:
        input_binary = st.text_input("📥 输入16位二进制明文/密文：", value="", max_chars=16, key="input_binary_double")
    with col2:
        key_32bit = st.text_input("🔑 输入32位二进制密钥：", value="", max_chars=32, key="key_32bit")

    col3, col4 = st.columns(2)
    with col3:
        if st.button("🔒 双重加密", key="double_encrypt"):
            if len(input_binary) == 16 and len(key_32bit) == 32 and all(c in '01' for c in key_32bit):
                ciphertext = double_encrypt(input_binary, key_32bit)
                st.session_state['double_ciphertext'] = ciphertext  # 保存到会话状态
                st.success(f"✅ 双重加密结果：`{ciphertext}`")
            else:
                st.error("⚠️ 请输入16位明文和32位二进制密钥。")
    with col4:
        if st.button("🔓 双重解密", key="double_decrypt"):
            if len(input_binary) == 16 and len(key_32bit) == 32 and all(c in '01' for c in key_32bit):
                decrypted_text = double_decrypt(st.session_state.get('double_ciphertext', input_binary), key_32bit)
                st.success(f"✅ 双重解密结果：`{decrypted_text}`")
            else:
                st.error("⚠️ 请输入16位密文和32位二进制密钥。")

    st.markdown("### 🕵️‍♂️ 中间相遇攻击")
    st.markdown("尝试通过中间相遇攻击找到可能的密钥组合。")

    if st.button("⚔️ 执行中间相遇攻击", key="meet_in_the_middle_attack"):
        if len(input_binary) == 16 and len(key_32bit) == 32 and all(c in '01' for c in key_32bit):
            with st.spinner("🔍 正在执行中间相遇攻击..."):
                possible_keys = meet_in_the_middle_attack(input_binary, key_32bit)
            if possible_keys:
                st.success("✅ 找到的可能密钥组合 (K1, K2)：")
                for idx, (k1, k2) in enumerate(possible_keys[:5], 1):  # 显示前五个组合
                    st.write(f"{idx}. **K1**: `{k1}` , **K2**: `{k2}`")
            else:
                st.warning("⚠️ 未找到密钥组合。")
        else:
            st.error("⚠️ 请输入正确格式的16位明文和32位密钥进行中间相遇攻击。")

# Tab 4: 三重加密/解密
with tab4:
    st.header("🔑 三重加密/解密")
    st.markdown("进行三重加密和解密操作。")

    col1, col2 = st.columns(2)
    with col1:
        input_binary_48 = st.text_input("📥 输入16位二进制明文/密文：", value="", max_chars=16, key="input_binary_48")
    with col2:
        key_48bit = st.text_input("🔑 输入48位二进制密钥：", value="", max_chars=48, key="key_48bit")

    col3, col4 = st.columns(2)
    with col3:
        if st.button("🔒 三重加密", key="triple_encrypt"):
            if len(input_binary_48) == 16 and len(key_48bit) == 48 and all(c in '01' for c in key_48bit):
                ciphertext = triple_encrypt(input_binary_48, key_48bit)
                st.session_state['triple_ciphertext'] = ciphertext  # 保存到会话状态
                st.success(f"✅ 三重加密结果：`{ciphertext}`")
            else:
                st.error("⚠️ 请输入16位明文和48位二进制密钥。")
    with col4:
        if st.button("🔓 三重解密", key="triple_decrypt"):
            if len(input_binary_48) == 16 and len(key_48bit) == 48 and all(c in '01' for c in key_48bit):
                decrypted_text = triple_decrypt(st.session_state.get('triple_ciphertext', input_binary_48), key_48bit)
                st.success(f"✅ 三重解密结果：`{decrypted_text}`")
            else:
                st.error("⚠️ 请输入16位密文和48位二进制密钥。")

# Tab 5: CBC 加密/解密
with tab5:
    st.header("🔒 CBC 模式加密/解密")
    st.markdown("""
    使用 CBC 模式进行加密和解密。支持篡改密文模拟以测试加密的稳健性。
    """)

    # 在会话开始时生成并存储 IV，如果尚未生成
    if 'cbc_iv' not in st.session_state:
        st.session_state['cbc_iv'] = generate_iv()
        st.session_state['cbc_ciphertext'] = ""  # 初始化密文存储
        st.session_state['cbc_tampered_ciphertext'] = ""  # 初始化篡改密文存储

    iv = st.session_state['cbc_iv']

    st.info(f"🔑 **初始向量 (IV)**：`{iv}`")

    col1, col2 = st.columns(2)
    with col1:
        plaintext = st.text_area("📥 输入二进制明文（长度为16的倍数）：", value="", key="plaintext_cbc")
    with col2:
        key_cbc = st.text_input("🔑 输入16位二进制密钥：", value="", max_chars=16, key="key_cbc_cbc")

    col3, col4 = st.columns(2)
    with col3:
        if st.button("🔒 CBC 加密", key="cbc_encrypt"):
            # 验证输入是否为二进制且长度正确
            if len(key_cbc) == 16 and all(c in '01' for c in key_cbc):
                if len(plaintext) == 0:
                    st.error("⚠️ 明文不能为空。")
                elif len(plaintext) % 16 != 0:
                    st.error("⚠️ 明文长度必须是16的倍数。")
                elif not all(c in '01' for c in plaintext):
                    st.error("⚠️ 明文必须是二进制字符串（仅包含0和1）。")
                else:
                    ciphertext = encrypt_cbc(plaintext, key_cbc, iv)
                    st.session_state['cbc_ciphertext'] = ciphertext  # 保存到会话状态
                    st.session_state['cbc_tampered_ciphertext'] = ""  # 重置篡改密文
                    st.success(f"✅ CBC 加密结果：`{ciphertext}`")
            else:
                st.error("⚠️ 请输入16位二进制密钥。")
    with col4:
        if st.button("⚠️ 模拟篡改密文", key="simulate_tampering"):
            if st.session_state['cbc_ciphertext']:
                original_cipher = st.session_state['cbc_ciphertext']
                # 确保密文长度足够
                if len(original_cipher) >= 10:
                    # 将前10位改为 '1010101010'，保留剩余部分
                    tampered_cipher = '1010101010' + original_cipher[10:]
                    st.session_state['cbc_tampered_ciphertext'] = tampered_cipher
                    st.success(f"✅ 篡改后的密文：`{tampered_cipher}`")
                else:
                    st.error("⚠️ 密文长度不足以篡改前10位。")
            else:
                st.error("⚠️ 请先进行 CBC 加密以生成密文。")

    # 显示篡改后的密文
    if st.session_state['cbc_tampered_ciphertext']:
        st.markdown("### 🛠️ 篡改后的密文")
        st.code(st.session_state['cbc_tampered_ciphertext'], language='binary')

    col5, col6 = st.columns(2)
    with col5:
        if st.button("🔓 CBC 解密（原密文）", key="cbc_decrypt_original"):
            if st.session_state['cbc_ciphertext']:
                decrypted_text = decrypt_cbc(st.session_state['cbc_ciphertext'], key_cbc, iv)
                st.success(f"✅ 解密原密文结果：`{decrypted_text}`")
            else:
                st.error("⚠️ 请先进行 CBC 加密以生成密文。")
    with col6:
        if st.button("🔓 CBC 解密（篡改密文）", key="cbc_decrypt_tampered"):
            if st.session_state['cbc_tampered_ciphertext']:
                decrypted_tampered_text = decrypt_cbc(st.session_state['cbc_tampered_ciphertext'], key_cbc, iv)
                st.success(f"✅ 篡改密文解密结果：`{decrypted_tampered_text}`")
            else:
                st.error("⚠️ 请先进行 CBC 加密并模拟篡改密文。")

    # 提供下载按钮以下载密文
    if st.session_state['cbc_ciphertext']:
        st.markdown("---")
        st.download_button(
            label="💾 下载原密文",
            data=st.session_state['cbc_ciphertext'],
            file_name='cbc_ciphertext.txt',
            mime='text/plain'
        )
    if st.session_state['cbc_tampered_ciphertext']:
        st.download_button(
            label="💾 下载篡改后的密文",
            data=st.session_state['cbc_tampered_ciphertext'],
            file_name='cbc_tampered_ciphertext.txt',
            mime='text/plain'
        )

# 页脚
st.markdown("---")
st.markdown("""
指导老师：陈欣

""")
st.markdown("""
开发成员：李昊轩，史亚涛
""")
