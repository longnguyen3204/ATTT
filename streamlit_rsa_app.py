import streamlit as st
import random
import hashlib
import time
import os
import pandas as pd
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, SECP256k1

# Khởi tạo cấu hình trang Streamlit
st.set_page_config(
    page_title="Hệ thống Mật mã và Đánh giá Hiệu năng RSA",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# CÁC MODULE MẬT MÃ CƠ SỞ
# ==========================================
class RSACore:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        # CRT parameters
        self.dp = None
        self.dq = None
        self.qinv = None
        self.p = None
        self.q = None

    def _is_prime(self, n, k=40):
        if n == 2 or n == 3: return True
        if n <= 1 or n % 2 == 0: return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else:
                return False
        return True

    def _generate_large_prime(self, bits):
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if self._is_prime(num): return num

    def _extended_gcd(self, a, b):
        if a == 0: return b, 0, 1
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def _mod_inverse(self, e, phi):
        gcd, x, y = self._extended_gcd(e, phi)
        if gcd != 1: raise Exception("Khong co nghich dao mo-dun")
        return x % phi

    def generate_keypair(self):
        prime_size = self.key_size // 2
        p = self._generate_large_prime(prime_size)
        q = self._generate_large_prime(prime_size)
        while p == q: q = self._generate_large_prime(prime_size)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if self._extended_gcd(e, phi)[0] != 1:
            e = random.randrange(3, phi - 1, 2)
        d = self._mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        # Calculate CRT parameters
        self.p = p
        self.q = q
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)
        self.qinv = self._mod_inverse(q, p)

        return (e, n), (d, n), p, q

    def encrypt_textbook(self, plaintext_int):
        if not self.public_key:
            return None
        e, n = self.public_key
        return pow(plaintext_int, e, n)

    def decrypt_textbook(self, ciphertext_int):
        if not self.private_key:
            return None
        d, n = self.private_key
        return pow(ciphertext_int, d, n)
        
    def decrypt_crt(self, ciphertext_int):
        # Giai ma su dung Dinh ly So du Trung Hoa (CRT)
        if not self.private_key or not self.p:
            return None
        
        # m1 = c^dp mod p
        m1 = pow(ciphertext_int, self.dp, self.p)
        # m2 = c^dq mod q
        m2 = pow(ciphertext_int, self.dq, self.q)
        
        # h = qinv * (m1 - m2) mod p
        h = (self.qinv * (m1 - m2)) % self.p
        
        # m = m2 + h * q
        m = m2 + h * self.q
        return m

    def sign(self, message_string):
        if not self.private_key:
            return None
        d, n = self.private_key
        hash_digest = hashlib.sha256(message_string.encode('utf-8')).hexdigest()
        hash_int = int(hash_digest, 16)
        # Using CRT for signing is faster
        if self.p:
            return self.decrypt_crt(hash_int)
        return pow(hash_int, d, n)

    def verify(self, message_string, signature):
        if not self.public_key:
            return False
        e, n = self.public_key
        hash_digest = hashlib.sha256(message_string.encode('utf-8')).hexdigest()
        expected_hash_int = int(hash_digest, 16)
        actual_hash_int = pow(signature, e, n)
        return expected_hash_int == actual_hash_int

class RSA_AES_Hybrid:
    def __init__(self, rsa_instance):
        self.rsa = rsa_instance

    def encrypt(self, plaintext_bytes):
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_bytes)
        
        aes_key_int = int.from_bytes(aes_key, 'big')
        encrypted_aes_key = self.rsa.encrypt_textbook(aes_key_int)
        
        return encrypted_aes_key, cipher_aes.nonce, tag, ciphertext

    def decrypt(self, encrypted_aes_key, nonce, tag, ciphertext):
        # Use CRT for faster decryption of AES key
        decrypted_aes_key_int = self.rsa.decrypt_crt(encrypted_aes_key)
        aes_key = decrypted_aes_key_int.to_bytes(32, 'big')
        
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return plaintext_bytes

# ==========================================
# STREAMLIT INTERFACE
# ==========================================
st.title("Ứng dụng Mô phỏng & Đánh giá Hiệu năng Mật mã RSA")
st.markdown("---")

if 'rsa' not in st.session_state:
    st.session_state.rsa = RSACore(key_size=1024)
    st.session_state.keys_generated = False
    st.session_state.pub_key = None
    st.session_state.priv_key = None

st.sidebar.header("Cấu hình hệ thống")
key_size_choice = st.sidebar.selectbox("Kích thước khóa RSA (Bits)", [512, 1024, 2048, 3076], index=1)

if st.sidebar.button("Sinh Cặp Khóa Mới"):
    with st.spinner("Đang khởi tạo các số nguyên tố lớn và sinh khóa..."):
        st.session_state.rsa = RSACore(key_size=key_size_choice)
        pub, priv, p, q = st.session_state.rsa.generate_keypair()
        st.session_state.pub_key = pub
        st.session_state.priv_key = priv
        st.session_state.p = p
        st.session_state.q = q
        st.session_state.keys_generated = True
    st.sidebar.success("Đã sinh khóa thành công!")

if st.session_state.keys_generated:
    st.sidebar.info(f"**Trạng thái:** Khóa {key_size_choice}-bit Sẵn sàng")
    with st.sidebar.expander("Xem chi tiết các tham số khóa"):
        st.text_area("Khóa công khai (e, n)", str(st.session_state.pub_key), height=70)
        st.text_area("Số nguyên tố p", str(st.session_state.p), height=50)
        st.text_area("Số nguyên tố q", str(st.session_state.q), height=50)
else:
    st.sidebar.warning("Vui lòng bấm 'Sinh Cặp Khóa Mới' để bắt đầu.")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "1. Mã hóa RSA Chuẩn", 
    "2a. Mã hóa Lai RSA + AES", 
    "2b. Chữ ký số SHA-256", 
    "3. Đánh giá Hiệu năng",
    "4. Fast RSA (CRT)"
])

with tab1:
    st.header("Mã hóa và Giải mã RSA Chuẩn (Textbook RSA)")
    st.caption("Lưu ý: RSA chuẩn chỉ mã hóa được các chuỗi dữ liệu có kích thước nhỏ hơn kích thước khóa.")
    
    if not st.session_state.keys_generated:
        st.warning("Vui lòng sinh khóa ở thanh điều hướng bên trái trước.")
    else:
        text_input = st.text_input("Nhập văn bản cần mã hóa (Chuỗi ngắn):", "LỚP_AN_TOÀN_THÔNG_TIN")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Thực hiện Mã hóa RSA"):
                msg_int = int.from_bytes(text_input.encode('utf-8'), 'big')
                if msg_int >= st.session_state.pub_key[1]:
                    st.error("Lỗi: Độ dài văn bản vượt quá dung lượng tối đa của khóa hiện tại!")
                else:
                    st.session_state.tab1_cipher_int = st.session_state.rsa.encrypt_textbook(msg_int)
                    st.success("Mã hóa thành công!")
                    st.text_area("Bản mã dữ liệu (Dạng Số Nguyên lớn):", str(st.session_state.tab1_cipher_int), height=100)
        
        with col2:
            if 'tab1_cipher_int' in st.session_state:
                if st.button("Thực hiện Giải mã RSA"):
                    decrypted_int = st.session_state.rsa.decrypt_textbook(st.session_state.tab1_cipher_int)
                    try:
                        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
                        decrypted_text = decrypted_bytes.decode('utf-8')
                        st.success("Giải mã thành công!")
                        st.info(f"Kết quả giải mã: **{decrypted_text}**")
                    except Exception as e:
                        st.error(f"Lỗi giải mã hoặc định dạng chuỗi: {str(e)}")

with tab2:
    st.header("Thuật toán mã hóa lai: Kết hợp RSA và đối xứng AES")
    if not st.session_state.keys_generated:
        st.warning("Vui lòng sinh khóa ở thanh điều hướng bên trái trước.")
    else:
        uploaded_file = st.file_uploader("Tải lên file (PDF, DOCX, TXT, PNG) cần mã hóa lai:", type=['txt', 'pdf', 'docx', 'png'])
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Mã hóa Lai (RSA + AES)"):
                if uploaded_file is not None:
                    file_bytes = uploaded_file.read() 
                    hybrid_sys = RSA_AES_Hybrid(st.session_state.rsa)
                    st.session_state.hybrid_data = hybrid_sys.encrypt(file_bytes)
                    st.session_state.original_filename = uploaded_file.name
                    st.success("Mã hóa xong!")
                    st.metric(label="Kích thước Bản mã AES (Bytes)", value=len(st.session_state.hybrid_data[3]))
                else:
                    st.error("Vui lòng tải lên một tệp tin trước khi mã hóa.")
                    
        with col2:
            if 'hybrid_data' in st.session_state:
                if st.button("Giải mã Lai (RSA + AES)"):
                    hybrid_sys = RSA_AES_Hybrid(st.session_state.rsa)
                    enc_key, nonce, tag, ciphertext = st.session_state.hybrid_data
                    try:
                        decrypted_bytes = hybrid_sys.decrypt(enc_key, nonce, tag, ciphertext)
                        st.success("Hệ thống giải mã lai thành công!")
                        st.download_button(
                            label="Tải xuống file đã giải mã",
                            data=decrypted_bytes,
                            file_name=f"decrypted_{st.session_state.get('original_filename', 'file.bin')}"
                        )
                    except Exception as e:
                        st.error(f"Xác thực dữ liệu thất bại: {str(e)}")

with tab3:
    st.header("Chữ ký số RSA kết hợp Hàm băm định danh SHA-256")

    if not st.session_state.keys_generated:
        st.warning("Vui lòng sinh khóa ở thanh điều hướng bên trái trước.")

    else:
        # Upload file để ký
        sign_file = st.file_uploader(
            "Tải tài liệu lên để Ký số:",
            key="upload_sign"
        )

        # Nút tạo chữ ký
        if st.button("Tạo Chữ ký số"):

            if sign_file is not None:
                # Đọc nội dung file
                content_to_sign = sign_file.read().decode(
                    'utf-8',
                    errors='ignore'
                )

                # Ký số
                st.session_state.signature = (
                    st.session_state.rsa.sign(content_to_sign)
                )

                st.success("Đã tạo chữ ký số thành công!")
                
                st.text_area(
                    "Chữ ký số sản sinh:",
                    str(st.session_state.signature),
                    height=100
                )

            else:
                st.error("Vui lòng tải file lên để tạo chữ ký.")

        # Phần xác thực
        if 'signature' in st.session_state:

            st.subheader("Kiểm thử và xác thực chữ ký")

            verify_file = st.file_uploader(
                "Tải tài liệu lên để kiểm tra tính toàn vẹn:",
                key="upload_verify"
            )

            if st.button("Xác thực tính chính xác"):

                if verify_file is not None:

                    content_to_verify = verify_file.read().decode(
                        'utf-8',
                        errors='ignore'
                    )

                    if st.session_state.rsa.verify(
                        content_to_verify,
                        st.session_state.signature
                    ):
                        st.success(
                            "✅ Xác thực THÀNH CÔNG: Tài liệu toàn vẹn!"
                        )
                    else:
                        st.error(
                            "CẢNH BÁO: Xác thực THẤT BẠI! "
                            "Tài liệu đã bị chỉnh sửa."
                        )

                else:
                    st.error("Vui lòng tải file lên để xác thực.")


with tab4:
    st.header("Đánh giá, đo lường và so sánh hiệu năng")
    st.write("Đo lường thời gian thực của các thuật toán mã hóa dữ liệu.")
    
    # THÊM SỐ LIỆU: Bổ sung thanh trượt để thay đổi độ dài khóa trực tiếp cho bài test
    st.markdown("Bạn có thể điều chỉnh linh hoạt các thông số dưới đây để xem sự thay đổi hiệu năng:")
    col_a, col_b = st.columns(2)
    with col_a:
        data_size_kb = st.slider("Kích thước tệp tin giả lập (KB)", 10, 2048, 500, step=50)
    with col_b:
        benchmark_key_size = st.selectbox("Kích thước khóa RSA dùng cho Test (Bits)", [512, 1024, 2048], index=1)
    
    if st.button("Chạy Đánh giá Hiệu năng (Real-time Benchmark)"):
        with st.spinner("Hệ thống đang tiến hành đo đạc hiệu năng..."):
            # Sinh khóa tạm thời phục vụ benchmark
            temp_rsa = RSACore(key_size=benchmark_key_size)
            temp_rsa.generate_keypair()
            hybrid_sys = RSA_AES_Hybrid(temp_rsa)
            
            test_bytes = os.urandom(data_size_kb * 1024)
            small_bytes = os.urandom(64)
            
            # 1. Đo lường AES 256-bit
            aes_key = get_random_bytes(32)
            t_start = time.perf_counter()
            cipher_encrypt = AES.new(aes_key, AES.MODE_EAX)
            c_text, tag = cipher_encrypt.encrypt_and_digest(test_bytes)
            t_enc_aes = (time.perf_counter() - t_start) * 1000
            
            t_start = time.perf_counter()
            cipher_decrypt = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_encrypt.nonce)
            cipher_decrypt.decrypt_and_verify(c_text, tag)
            t_dec_aes = (time.perf_counter() - t_start) * 1000
            
            # 2. Đo lường RSA thuần
            data_int = int.from_bytes(small_bytes, 'big')
            t_start = time.perf_counter()
            rsa_cipher = temp_rsa.encrypt_textbook(data_int)
            t_enc_rsa = (time.perf_counter() - t_start) * 1000
            
            t_start = time.perf_counter()
            temp_rsa.decrypt_textbook(rsa_cipher)
            t_dec_rsa = (time.perf_counter() - t_start) * 1000
            
            # 3. Đo lường Hệ Lai (RSA + AES)
            t_start = time.perf_counter()
            h_key, h_nonce, h_tag, h_cipher = hybrid_sys.encrypt(test_bytes)
            t_enc_hybrid = (time.perf_counter() - t_start) * 1000
            
            t_start = time.perf_counter()
            hybrid_sys.decrypt(h_key, h_nonce, h_tag, h_cipher)
            t_dec_hybrid = (time.perf_counter() - t_start) * 1000
            
            # 4. Đo lường Chữ ký số
            msg_sign = b"Test signature document"
            t_start = time.perf_counter()
            rsa_sig = temp_rsa.sign(msg_sign.decode('utf-8'))
            t_sign_rsa = (time.perf_counter() - t_start) * 1000
            
            t_start = time.perf_counter()
            temp_rsa.verify(msg_sign.decode('utf-8'), rsa_sig)
            t_verify_rsa = (time.perf_counter() - t_start) * 1000
            
            sk = SigningKey.generate(curve=SECP256k1)
            vk = sk.verifying_key
            t_start = time.perf_counter()
            ecc_sig = sk.sign(msg_sign)
            t_sign_ecc = (time.perf_counter() - t_start) * 1000
            
            t_start = time.perf_counter()
            vk.verify(ecc_sig, msg_sign)
            t_verify_ecc = (time.perf_counter() - t_start) * 1000
            
        st.success("Đã hoàn tất đo lường số liệu!")
        
        st.subheader("1. So sánh thời gian xử lý Mã hóa & Giải mã")
        crypto_data = {
            'Thuật toán': ['AES (Đới xứng)', 'Lai (RSA+AES)', 'RSA Thuần (64B)'],
            'Mã hóa (ms)': [t_enc_aes, t_enc_hybrid, t_enc_rsa],
            'Giải mã (ms)': [t_dec_aes, t_dec_hybrid, t_dec_rsa],
            'Thông lượng (MB/s)': [
                (data_size_kb / 1024) / (t_enc_aes / 1000) if t_enc_aes > 0 else 0,
                (data_size_kb / 1024) / (t_enc_hybrid / 1000) if t_enc_hybrid > 0 else 0,
                (64 / (1024 * 1024)) / (t_enc_rsa / 1000) if t_enc_rsa > 0 else 0
            ]
        }
        df_crypto = pd.DataFrame(crypto_data)
        st.dataframe(df_crypto.style.format({'Mã hóa (ms)': '{:.4f}', 'Giải mã (ms)': '{:.4f}', 'Thông lượng (MB/s)': '{:.4f}'}))
        
        fig1, ax1 = plt.subplots(figsize=(10, 4))
        df_crypto.set_index('Thuật toán')[['Mã hóa (ms)', 'Giải mã (ms)']].plot(kind='bar', ax=ax1, rot=0)
        ax1.set_ylabel("Thời gian (ms)")
        st.pyplot(fig1)
        
        st.markdown("---")
        st.subheader("2. Hiệu năng Chữ ký số")
        df_sig = pd.DataFrame({
            'Thuật toán': ['RSA', 'ECC'],
            'Ký (ms)': [t_sign_rsa, t_sign_ecc],
            'Xác thực (ms)': [t_verify_rsa, t_verify_ecc]
        })
        st.dataframe(df_sig)
        
        fig2, ax2 = plt.subplots(figsize=(10, 4))
        df_sig.set_index('Thuật toán').plot(kind='bar', ax=ax2, rot=0)
        ax2.set_ylabel("Thời gian (ms)")
        st.pyplot(fig2)


with tab5:
    st.header("So sánh Giải thuật RSA Thuần vs Fast RSA (CRT)")
    
    if not st.session_state.keys_generated:
        st.warning("Vui lòng sinh khóa ở thanh điều hướng bên trái trước.")
    else:
        st.markdown("Kiểm tra tốc độ giải mã sử dụng Định lý Số dư Trung Hoa (CRT).")
        
        # Bổ sung tính năng tự điền số nguyên m để test theo ý muốn
        user_test_msg = st.text_input("Nhập chuỗi văn bản (hoặc số) tùy chọn để kiểm thử tốc độ giải mã:", "Hello RSA CRT Performance Test!")
        num_iterations = st.slider("Số vòng lặp kiểm thử (để lấy trung bình):", 10, 500, 100)
        
        if st.button("Chạy So sánh Hiệu năng CRT"):
            with st.spinner("Đang thực hiện tính toán..."):
                test_msg_int = int.from_bytes(user_test_msg.encode('utf-8'), 'big')
                if test_msg_int >= st.session_state.pub_key[1]:
                     st.error("Lỗi: Dữ liệu nhập vào quá lớn so với khóa hiện tại!")
                else:
                    cipher_msg = st.session_state.rsa.encrypt_textbook(test_msg_int)
                    
                    # Textbook RSA
                    start_time = time.perf_counter()
                    for _ in range(num_iterations):
                        st.session_state.rsa.decrypt_textbook(cipher_msg)
                    textbook_time = (time.perf_counter() - start_time) * 1000 / num_iterations
                    
                    # CRT RSA
                    start_time = time.perf_counter()
                    for _ in range(num_iterations):
                        st.session_state.rsa.decrypt_crt(cipher_msg)
                    crt_time = (time.perf_counter() - start_time) * 1000 / num_iterations
                    
                    speedup = textbook_time / crt_time if crt_time > 0 else 0
                    
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Giải mã Thường (ms/vòng)", f"{textbook_time:.4f}")
                    col2.metric("Giải mã CRT (ms/vòng)", f"{crt_time:.4f}")
                    col3.metric("Tốc độ tăng lên", f"{speedup:.2f}x")
                    
                    st.success(f"Dữ liệu kiểm thử: **'{user_test_msg}'**. CRT nhanh hơn khoảng **{speedup:.2f} lần**.")


# Kích hoạt môi trường ảo: .venv\Scripts\activate
# Chạy code: streamlit run streamlit_rsa_app.py
