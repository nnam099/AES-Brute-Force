"""Theory / reference tab — extracted from gui.py."""

from __future__ import annotations

import tkinter as tk
import customtkinter as ctk

from aes_brute_force.gui import theme as T

_CONTENT = """\
GHI CHÚ LÝ THUYẾT CHO THÍ NGHIỆM AES
==========================================================

1. AES dùng trong chương trình
----------------------------------------------------------
AES là mã khối đối xứng. Trong đồ án này chỉ xét AES-128:

  - kích thước khối: 128 bit = 16 byte
  - kích thước khóa thật của AES-128: 128 bit
  - số vòng biến đổi: 10 vòng
  - chế độ minh họa: ECB

Mỗi khối bản rõ P được mã hóa thành bản mã C theo khóa K:

  C = E_K(P)
  P = D_K(C)

2. Vì sao vẫn vét cạn được trong demo
----------------------------------------------------------
AES-128 đầy đủ có 2^128 khóa, không thể duyệt hết bằng máy
tính thông thường. Để quan sát được quá trình vét cạn, đồ án
chỉ giữ bí mật n bit đầu của khóa, phần còn lại điền 0x00.

Ví dụ với khóa 16 bit:

  phần bí mật      : AB CD
  khóa AES-128     : AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  không gian khóa  : |K| = 2^16 = 65,536 khóa

3. Cách vét cạn
----------------------------------------------------------
Với n bit bí mật, chương trình thử 0, 1, 2, ..., 2^n - 1.
Mỗi giá trị i được đổi thành khóa AES-128 dạng:

  key = bytes(i) || 00 ... 00

Kiểm tra:  PKCS#7 padding hợp lệ + tỉ lệ ASCII ≥ 90%.

4. Ước tính thời gian
----------------------------------------------------------
  Trung bình : T_avg   = 2^(n-1) / R
  Xấu nhất   : T_worst = 2^n / R

Khi tăng n thêm 1 bit, thời gian tăng gấp đôi.

  8 bit   : 256 khóa
  16 bit  : 65,536 khóa
  24 bit  : 16,777,216 khóa
  128 bit : 3.4 × 10^38 khóa

5. Lưu ý về ECB
----------------------------------------------------------
ECB mã hóa từng khối độc lập → lộ mẫu lặp.
Thực tế nên dùng CBC/GCM. ECB ở đây chỉ để giữ demo đơn giản.

Tài liệu:
  - NIST FIPS-197, Advanced Encryption Standard
  - Stallings, Cryptography and Network Security
  - Paar, Understanding Cryptography
"""


class TheoryTab(ctk.CTkFrame):
    """Tab 3: AES theory reference notes."""

    def __init__(self, parent: ctk.CTkFrame, app=None) -> None:
        super().__init__(parent, fg_color="transparent")

        card = ctk.CTkFrame(self, fg_color=T.BG_SURFACE, corner_radius=12)
        card.pack(fill="both", expand=True)

        card_inner = ctk.CTkFrame(card, fg_color="transparent")
        card_inner.pack(fill="both", expand=True, padx=30, pady=30)

        txt = ctk.CTkTextbox(
            card_inner, font=T.FONT_MONO, fg_color=T.BG_BASE, text_color=T.FG_TEXT, border_width=0
        )
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", _CONTENT)
        txt.configure(state="disabled")
