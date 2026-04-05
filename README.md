# Bài Tập Lớn: Lập Trình Driver Khóa Linux

Kho lưu trữ này chứa hai đồ án thực hành môn lập trình Device Driver trên nhân hệ điều hành Linux (Ubuntu). 

Dự án được chia làm 2 bài tập độc lập với các thư mục riêng rẽ:

### 📁 1. Thư mục `bai1_crypto_camellia`
- **Mô tả ngắn**: Bài tập tạo ra hệ thống bảo mật file thông qua module hạt nhân (Kernel module).
- **Tính năng nổi bật**: Không tự code thuật toán mà kết nối vào **Linux Crypto API**, tận dụng sức mạnh cấp phần cứng của thuật toán mã hóa đối xứng **CAMELLIA (128-bit CBC mode)** để khoá và giải mã dữ liệu của người dùng. Kèm theo cơ chế Padding PKCS#7.
- **Cách xem**: Bên trong có 1 app Userspace (`file_manager`) và 1 Driver `camellia_drv.c`. Chi tiết luồng và cách build xin đọc `README.md` bên trong thư mục đó.

### 📁 2. Thư mục `bai2_usb_mouse`
- **Mô tả ngắn**: Bài tập thực hành về giao thức kết nối Input Subsystem & USB Core.
- **Tính năng nổi bật**: Viết Driver mới hoàn toàn, chiếm quyền điều khiển của bất kỳ con chuột USB chuẩn nào được cắm vào máy (`Hooking`). Driver này đứng ra nhận thao tác của chuột, nhưng khi phát hiện cú bấm con lăn/chuột giữa, thay vì gửi click chuột, nhét một chuỗi tín hiệu bàn phím đánh lừa hệ điều hành in ra chữ **"Hello PhongPKF"**.
- **Cách xem**: Bên trong chứa code gốc `phong_mouse.c` và kịch bản Bash tự gỡ chuột. Chi tiết xin xem trong `README.md` của thư mục tương ứng.

---

### 🖥️ Môi trường thực thi khuyến nghị:
- **Hệ điều hành**: Linux Kernel 5.x / 6.x trở lên (Test tốt trên Ubuntu 22.04 / 24.04).
- **Công cụ**: Yêu cầu cài đặt sẵn gói `build-essential` và `linux-headers`.

> [!WARNING]
> **Cấu hình bắt buộc khi chạy Bài 2 trên máy ảo VMware:**
> Do VMware có tính năng "hút" tương tác chuột ẩn qua một lớp Hypervisor, Driver USB của chúng ta sẽ không nhận được tín hiệu nếu không pass-through (đưa thẳng) chuột vật lý vào máy ảo. 
> 
> **Các bước ép VMware hiển thị chuột USB:**
> 1. Tắt (Power Off) hoàn toàn máy ảo Ubuntu và đóng giao diện phần mềm VMware.
> 2. Mở thư mục gốc chứa cục máy ảo trên máy thật bên ngoài của bạn.
> 3. Tìm file cấu trúc thiết lập có đuôi `.vmx` (Ví dụ: `Ubuntu.vmx`) và chuột phải, chọn Edit bằng Notepad.
> 4. Thêm 2 dòng lệnh bắt buộc sau vào dưới cùng của file Notepad:
>    ```ini
>    usb.generic.allowHID = "TRUE"
>    usb.generic.allowLastHID = "TRUE"
>    ```
> 5. Bấm Lưu (Ctrl+S) và mở lại máy ảo. Bạn có thể chộp con chuột vào máy ảo bằng thẻ menu: *VM → Removable Devices → [Tên Chuột của bạn] → Connect*.
