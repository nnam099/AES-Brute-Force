# GHI CHÚ LÝ THUYẾT CHO THÍ NGHIỆM AES BRUTE-FORCE
==========================================================

Tài liệu này cung cấp nền tảng lý thuyết mật mã học giải thích cơ chế hoạt động của thuật toán AES-128 và phương pháp tấn công vét cạn (Brute-Force Attack) được hiện thực hóa trong đồ án này.

## 1. Cơ sở lý thuyết về AES-128 trong hệ thống
----------------------------------------------------------
AES (Advanced Encryption Standard) là chuẩn mã hóa khối đối xứng được NIST công bố qua tài liệu FIPS-197. Trong phạm vi của đồ án, hệ thống mô phỏng chuẩn AES-128 với các đặc tả kỹ thuật sau:

- **Kích thước khối (Block Size):** 128 bits (16 bytes). Mỗi thao tác mã hóa/giải mã được xử lý độc lập trên từng ma trận trạng thái (State Matrix) kích thước 4x4 bytes.
- **Kích thước khóa (Key Size):** 128 bits (16 bytes).
- **Số vòng biến đổi (Rounds):** 10 vòng, bao gồm 9 vòng tiêu chuẩn (thực hiện đủ `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`) và 1 vòng cuối (bỏ qua `MixColumns`).
- **Chế độ hoạt động (Mode of Operation):** ECB (Electronic Codebook). Đây là chế độ mã hóa cơ bản nhất, mỗi khối bản rõ (Plaintext) $P_i$ được mã hóa thành khối bản mã (Ciphertext) $C_i$ một cách độc lập:
  - Quá trình mã hóa: $C_i = E_K(P_i)$
  - Quá trình giải mã: $P_i = D_K(C_i)$

Đặc biệt, hệ thống sử dụng thuật toán toán học thuần túy trên trường lũy thừa Galois $GF(2^8)$, không phụ thuộc vào bất kỳ thư viện tối ưu hóa nào (như PyCryptodome), nhằm phục vụ việc phân tích học thuật.

## 2. Bài toán entropy và tính khả thi của kỹ thuật Vét cạn
----------------------------------------------------------
Không gian khóa lý thuyết của AES-128 là $2^{128}$ (tương đương khoảng $3.4 \times 10^{38}$ khóa). Việc thử toàn bộ không gian này vượt quá khả năng tính toán của mọi hệ thống siêu máy tính hiện tại. 

Để quan sát và chứng minh được cơ chế của tấn công vét cạn, đồ án sử dụng kỹ thuật **"Suy giảm Entropy có chủ đích" (Intentional Entropy Reduction)**:
Chương trình chỉ giữ bí mật $n$ bit đầu tiên của khóa (mang giá trị ngẫu nhiên), các bit còn lại được đệm bằng các byte Null (`0x00`).

**Ví dụ phân tích với khóa hệ 16-bit ($n=16$):**
- **Phần mang thông tin (Entropy):** 2 bytes đầu (vd: `AB CD`)
- **Cấu trúc khóa thực tế nạp vào lõi AES:** `AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00`
- **Không gian khóa phải duyệt ($|K|$):** $2^{16} = 65,536$ trường hợp.

Nhờ việc thu hẹp không gian tìm kiếm, máy tính thông thường có thể dễ dàng quét qua toàn bộ các hoán vị trong thời gian tính bằng giây, phục vụ mục đích minh họa thuật toán.

## 3. Thuật toán tấn công Vét cạn (Brute-Force Strategy)
----------------------------------------------------------
Mục tiêu của tấn công là tìm lại được khóa $K_{secret}$ trong không gian $2^n$ thông qua phép thử sai tuần tự. 

**Quy trình thực thi:**
1. Khởi tạo vòng lặp sinh khóa thử (Candidate Key) từ $i = 0$ đến $2^n - 1$.
2. Ánh xạ giá trị nguyên $i$ thành mảng byte và padding chuỗi byte đó bằng `0x00` để đạt đủ 16 bytes.
3. Giải mã bản mã mục tiêu bằng khóa thử: $P'_{i} = D_{K_i}(C)$.
4. **Cơ chế đánh giá tự động (Heuristic Validation):** 
   Nếu $K_i \neq K_{secret}$, bản rõ $P'_i$ sẽ là một chuỗi byte ngẫu nhiên (tính chất thác khuếch tán của AES). Để máy tính tự nhận biết khóa đúng, hệ thống kiểm tra 2 điều kiện:
   - Tính toàn vẹn của Padding: Chuỗi giải mã phải thỏa mãn chuẩn PKCS#7.
   - Phân bố ký tự: Loại bỏ chuỗi chứa byte rác, đảm bảo trên 90% dữ liệu thuộc bảng mã ASCII có thể đọc được (Printable Text).

Hệ thống có thể kết hợp Đa tiến trình (Multiprocessing) để song song hóa không gian khóa, chia nhỏ số lượng cần quét cho từng lõi CPU.

## 4. Phân tích độ phức tạp thời gian (Time Complexity)
----------------------------------------------------------
Thời gian tìm kiếm phụ thuộc trực tiếp vào kích thước không gian khóa ($2^n$) và tốc độ giải mã của CPU ($R$ - keys/second).

- **Thời gian trung bình (Kỳ vọng):** $T_{avg} = \frac{2^{n-1}}{R}$
- **Thời gian xấu nhất (Phải duyệt đến khóa cuối):** $T_{worst} = \frac{2^n}{R}$

**Đặc tính tăng trưởng hàm mũ:** Cứ tăng thêm 1 bit độ dài khóa, chi phí tính toán và thời gian sẽ tăng gấp đôi.
- **8-bit:** $2^8 = 256$ khóa (Hoàn thành tức thời)
- **16-bit:** $2^{16} = 65,536$ khóa (Hoàn thành trong dưới 1 giây)
- **24-bit:** $2^{24} = 16,777,216$ khóa (Mất khoảng một vài phút)
- **128-bit:** $2^{128} \approx 3.4 \times 10^{38}$ khóa (Vượt quá độ tuổi vũ trụ)

## 5. Đánh giá rủi ro an toàn thông tin (Vulnerability of ECB)
----------------------------------------------------------
Mô hình mã hóa đang sử dụng là **Electronic Codebook (ECB)**. Đặc tính của ECB là tính tất định (Deterministic): Hai khối bản rõ $P_i$ và $P_j$ giống hệt nhau sẽ luôn sinh ra bản mã $C_i$ và $C_j$ giống hệt nhau nếu dùng chung một khóa.

**Hậu quả bảo mật:** 
- Rò rỉ cấu trúc dữ liệu (Data Pattern Leakage). Ví dụ kinh điển là "ECB Penguin" – khi mã hóa một bức ảnh bằng ECB, hình dáng cấu trúc ban đầu vẫn có thể nhìn thấy được bằng mắt thường.
- Không có cơ chế kiểm tra tính toàn vẹn (Integrity Authentication), dữ liệu mã hóa có thể bị thay đổi mà hệ thống giải mã không hề phát hiện ra (Bit-flipping attacks).

**Khuyến nghị thực tế:** Trong các ứng dụng công nghiệp, ECB được coi là không an toàn. Chuẩn hiện hành yêu cầu sử dụng các phương thức như **CBC (Cipher Block Chaining)** hoặc **GCM (Galois/Counter Mode)** kết hợp cùng Vector khởi tạo (IV/Nonce) và kiểm tra MAC (Message Authentication Code). ECB trong đồ án này được giữ lại vì tính đơn giản, phục vụ tốt nhất cho quan sát toán học lõi AES.

==========================================================
**Tài liệu Tham khảo (References):**
1. NIST FIPS-197, Advanced Encryption Standard.
2. William Stallings, "Cryptography and Network Security: Principles and Practice".
3. Christof Paar, Jan Pelzl, "Understanding Cryptography".
