# Báo Cáo Bài Tập: Quản Lý File Có Bảo Mật - CAMELLIA Driver

## 1. Lý Thuyết Tổng Quan

Bài tập yêu cầu xây dựng một hệ thống quản lý file an toàn gồm hai tầng: Userspace (App quản lý File) và Kernel space (Driver thực hiện việc mã hoá sử dụng thuật toán CAMELLIA). 

Sở dĩ phải triển khai nằm sâu trong Kernel thay vì App ở tầng trên tự mã hoá là để bảo mật khoá (key) và thuật toán khỏi các rủi ro từ Userspace (ví dụ bị dump RAM, bị malware đọc trộm). 

### 1.1 Khối Block Mã Hóa CAMELLIA (Symmetric Key Cipher)
CAMELLIA là một chuẩn mật mã khóa đối xứng ngang hàng với AES. Nó mã hoá từng cụm dữ liệu gọi là block. Block của CAMELLIA dài cố định 16 bytes.
Linux Kernel đã cấp sẵn bộ mã CAMELLIA này thông qua API gọi là **Linux Crypto API**, tối ưu hóa bằng hợp ngữ phần cứng khiến nó tính toán cưc kì nhanh chóng so với việc ta tự cấp phát vòng for.

### 1.2 Toán Tử "Độn" Dữ Liệu (PKCS#7 Padding)
Vì dữ liệu được băm nhỏ thành các cục 16 bytes, nếu kích thước File không chia hết cho 16 thì cục cuối cùng sẽ bị hụt. Do đó ta sử dụng thuật toán "độn":
* Nếu cụm cuối chỉ có 10 bytes tròn $\rightarrow$ thiếu 6 bytes.
* Ta sẽ "độn" liền tù tì 6 con số `0x06` vào 6 bytes bị thiếu đó. 

---

## 2. Giải Thích Luồng Xử Lý Mã Nguồn (`camellia_drv.c`)

### Bước 2.1: Nhận luồng văn bản từ File thông qua Kernel Buffer
Khi chạy lệnh `./file_manager encrypt secret.txt`, app sẽ bắn toàn bộ nội dung của file này xuống thiết bị ảo. Driver đón nội dung tại hàm `dev_write()`:
```c
static ssize_t dev_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset)
{
    struct camellia_state *state = filep->private_data;

    /* Cấp vùng nhớ động RAM phía Kernel tuỳ theo kích thước File thật đưa vào */
    state->in_buf = kmalloc(len, GFP_KERNEL);

    /* Chép dữ liệu gốc từ Userspace (RAM ứng dụng) xuống dải in_buf (RAM nhân) */
    copy_from_user(state->in_buf, buffer, len);
    state->in_len = len;

    return len;
}
```
Khác với lab6 chỉ dùng chuỗi `char message[1024]`, ở bài tập lớn chúng ta xử lý bất kỳ hệ file lớn/nhỏ thế nào nên dùng con trỏ `kmalloc(len)` tuỳ thuộc vào kích thước biến `len` do Client ra lệnh.

### Bước 2.2: Giao Thức Mã Hoá (Khởi tạo CAMELLIA API)
Ngay sau đó, App gọi lệnh IOCTL yêu cầu Kernel khoá đoạn dữ liệu lại. Tại hàm điều hướng `dev_ioctl`, đoạn code sẽ nhảy vào hàm `camellia_do_crypt()`.

Đây là quy trình thủ tục bắt buộc gọi Crypto API của Linux:
```c
// 1. Cấp phát engine giải mã CBC Mode / Camellia
struct crypto_skcipher *tfm = crypto_alloc_skcipher("cbc(camellia)", 0, 0);

// 2. Nạp KEY bảo mật (Dài 16 bytes)
crypto_skcipher_setkey(tfm, key, CAMELLIA_KEY_SIZE);

// 3. Tạo cấu trúc Object truy vấn của Kernel
struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);

// 4. Sinh bộ lập lịch Scatterlist để Kernel chọc hút vùng ram đầu vào(sg_in) trộn và đưa kết quả lưu thẳng ra vùng(sg_out)
sg_init_one(&sg_in, padded_in, padded_len);
sg_init_one(&sg_out, out, padded_len);

// Trỏ tham chiếu Object, sg_in, sg_out và biến khởi đệm ngẫu nhiên IV
skcipher_request_set_crypt(req, &sg_in, &sg_out, padded_len, iv);

// Bóp cò thực thi hàm băm mã hoá
ret = crypto_skcipher_encrypt(req);
```

### Bước 2.3: Toán Lượng Tính Padding (Độn vùng đệm)
Trước khi đoạn `crypto_skcipher_encrypt(req)` ở trên diễn ra, biến `padded_in` được Driver xây dựng độn đệm ra sao?
```c
if (encrypt) {
    /* Ép số thực tế lên thành bội số của 16 (Block size) */
    padded_len = ((in_len + CAMELLIA_BLOCK_SIZE) / CAMELLIA_BLOCK_SIZE) * CAMELLIA_BLOCK_SIZE;
    
    // Sao chép data gốc vào vùng nhớ đủ rộng (kèm dư dả)
    padded_in = kmalloc(padded_len, GFP_KERNEL);
    memcpy(padded_in, in, in_len);

    /* Nhồi thêm các dãy byte ảo PKCS#7 */
    u8 pad_val = (u8)(padded_len - in_len);
    memset(padded_in + in_len, pad_val, pad_val);
}
```

Ở chiều ngược lại khi giải mã (`decrypt`), cách cắt đệm cực kì ảo diệu: Thay vì duyệt tìm chữ, Driver chỉ cần đến tóm giá trị byte ở mút đuôi cùng, byte đuôi đó chứa con số bao nhiêu - thì Driver sẽ gọt đi đúng bấy nhiêu kích thước.

```c
/* Khi Decrypt giải mã ra text thành công, cần Xóa PKCS#7 padding */
u8 pad = out[padded_len - 1]; // Lấy giá trị của byte ở ô cuối bảng
*out_len = padded_len - pad;  // Chiều dài file gốc = Kích thước to - byte ảo
```

### 2.4 Quản trị Header Siêu Metadata (`app/file_manager.c`)
Nếu chỉ lưu nguyên ruột văn bản đã mã hoá, bản thân Driver sẽ không thể biết kích thước File gốc là bao nhiêu, và cả khoá IV giải mã ngẫu nhiên bị lạc đâu. 
Ở App phía Userspace, chúng ta tạo ra cấu trúc file `.enc` như sau để làm căn cước định danh dán chặt vào đầu File mã hoá:
```c
struct enc_header {
    char     magic[4];      /* Mã từ định danh tránh Fake format: "CAMF" */
    uint32_t orig_size;     /* 4 bytes - Nhớ chính xác kích thước file text gốc */
    uint8_t  iv[16];        /* 16 bytes - IV Random sinh ra độc nhất vô nhị */
};
```
Khi giải mã, `file_manager` sẽ kiểm duyệt cắt bỏ 24 bytes vùng này ra, trích xuất IV rồi nhét trở lại Driver để dịch ngược ruột File ciphertext ra thành chữ một cách hoàn hảo.

---

## 3. Hướng Dẫn Biên Dịch Và Chạy

### 3.1 Nạp Driver vào Kernel Linux
Mở Terminal, di chuyển vào thư mục `driver/` và biên dịch:
```bash
cd driver
make
```
Sau khi thấy thông báo biên dịch ra `camellia_drv.ko` thành công, bạn nạp Driver vào mạch máu của Kernel:
```bash
# Nạp thuật toán hỗ trợ của Linux nếu máy tính chưa sẵn sàng (Bắt buộc)
sudo modprobe camellia_generic

# Nạp Driver của bạn
sudo insmod camellia_drv.ko

# Kiểm tra xem máy ảo đã có thiết bị mã hoá chưa
ls -la /dev/camellia_drv
```

### 3.2 Biên Dịch Ứng Dụng CLI (terminal) & Test File Thực Tế
Sau khi có Driver, bạn lùi ra ngoài thư mục `app` để dùng công cụ test:
```bash
cd ../app
make
```
Để trải nghiệm hoàn chỉnh quá trình Mã hoá & Giải mã, gõ lần lượt các lệnh sau:
```bash
# 1. Tạo 1 file nội dung bí mật để mã hoá
echo "Mat khau wifi nha minh la: 12345678" > secret.txt

# 2. Ra lệnh App mã hoá file này
./file_manager encrypt secret.txt

# (Lúc này file secret.txt.enc ra đời, thư mục xuất hiện file có đuôi .enc)

# 3. Xem danh sách các mớ hỗn độn đã mã hoá
./file_manager list .

# 4. In thông tin đã giải mã ra màn hình ngay lập tức (In không cần xuất file)
./file_manager view secret.txt.enc

# 5. Khôi phục hoàn toàn thành định dạng text gốc thành file riêng (*.dec)
./file_manager decrypt secret.txt.enc
```
Để gỡ toàn bộ và hủy thiết bị, bạn chạy `sudo rmmod camellia_drv`.

---

### 3.3 Chạy Giao Diện GUI (PyQt6) - Ứng Dụng Đồ Họa

#### Bước 1: Cài đặt thư viện Python
```bash
pip install PyQt6
```
Hoặc nếu dùng `pip3`:
```bash
pip3 install PyQt6
```

#### Bước 2: Đảm bảo Driver đã được nạp
```bash
# Nếu chưa nạp, chạy lệnh sau:
cd driver
make
sudo modprobe camellia_generic
sudo insmod camellia_drv.ko

# Kiểm tra:
ls -la /dev/camellia_drv
```

#### Bước 3: Khởi chạy giao diện GUI
```bash
cd app
python3 file_manager_gui.py
```

#### Bước 4: Đăng nhập
Khi giao diện mở lên, bạn sẽ thấy **màn hình đăng nhập bảo mật**.  
Nhập mật khẩu: `haiproFF8604` rồi nhấn **ĐĂNG NHẬP** (hoặc nhấn Enter).

> **Lưu ý bảo mật:**
> - Mật khẩu được kiểm tra qua hàm băm SHA-256 (không lưu plaintext)
> - Nếu nhập sai 5 lần liên tục, tài khoản sẽ bị **khóa 30 giây**
> - Có hiệu ứng rung (shake) khi nhập sai mật khẩu

#### Bước 5: Sử dụng các chức năng

Sau khi đăng nhập thành công, giao diện chính gồm 4 tab:

| Tab | Chức năng |
|-----|-----------|
| 🔒 **Mã hóa** | Thêm file (đơn/nhiều/thư mục) → Mã hóa tất cả → file `.enc` |
| 🔓 **Giải mã** | Thêm file `.enc` (đơn/nhiều/thư mục) → Giải mã tất cả → file gốc |
| 📁 **Quản lý** | Quét thư mục, liệt kê file `.enc`, xem hoặc giải mã nhanh |
| 👁 **Xem file** | Chọn file `.enc`, xem nội dung đã giải mã (không cần xuất file) |

**Tính năng nổi bật:**
- ✅ **Mã hóa nhiều file cùng lúc** (batch processing)
- ✅ **Kéo thả file** trực tiếp vào giao diện
- ✅ **Thêm cả thư mục** (tự động quét tất cả file trong thư mục)
- ✅ **Xem nội dung file mã hóa** mà không cần giải mã ra file
- ✅ **Thanh tiến trình (progress bar)** theo dõi tiến độ xử lý
- ✅ **Nhật ký hoạt động** (log console) ghi lại mọi thao tác
- ✅ **Kiểm tra trạng thái driver** tự động mỗi 5 giây
- ✅ **Đăng xuất** khi muốn khóa lại ứng dụng

---

## 4. Cấu Trúc Thư Mục

```
bai1_crypto_camellia/
├── README.md                    # File hướng dẫn này
├── driver/
│   ├── camellia_drv.c           # Mã nguồn Kernel Driver
│   ├── camellia_drv.h           # Header định nghĩa IOCTL
│   ├── Makefile                 # Biên dịch driver
│   └── camellia_drv.ko          # Module kernel (sau khi make)
└── app/
    ├── file_manager.c           # Ứng dụng CLI (C)
    ├── file_manager_gui.py      # Ứng dụng GUI (Python/PyQt6) ← MỚI
    └── Makefile                 # Biên dịch app CLI
```
