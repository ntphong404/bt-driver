# Báo Cáo Bài Tập: USB Mouse Input Hack Driver (Giả Lập Bàn Phím Tự Động)

## 1. Lý Thuyết Tổng Quan

Bài tập này yêu cầu viết một Driver điều khiển cho chuột máy tính thông thường (chuẩn tín hiệu USB Boot Protocol) nhưng lại "bắt cóc" luồng dữ liệu, thực hiện tính năng "hack/badusb": Gửi sự kiện giả lập bàn phím thay vì sự kiện chuột khi phát hiện click núm giữa chuột. Ý tưởng này phản ánh chính xác cấu tạo của các dòng mã hóa phần cứng hiểm độc (gọi chung là BadUSB), khi một thiết bị USB được cắm vào để che mắt dưới dạng Chuột, nhưng âm thầm kích hoạt quyền hạn của Bàn phím để đánh cắp/ra lệnh giả lập siêu cấp.

### Trình Giao Tiếp Input Events Subsystem trong Linux
Trong Linux, tầng giao tiếp `Input Devices` là một tầng trừu tượng hoá. Nghĩa là thiết bị vật lý có thể là bất cứ thứ gì, nhưng Linux gom chung chúng về một nơi xử lý sự kiện:
- Nút bấm và Phím nhấn được quản lý bằng cơ chế chung `EV_KEY`.
- Trục tọa độ, vòng di chuyển gọi là `EV_REL` (Relative).

Theo đó một thiết bị tự nhận mình là Chuột Vật Lý có thể mạnh dạn xin Hệ Điều Hành để bản thân được phép sinh ra các tương tác kí tự mà hoàn toàn không gặp ngăn cản nào.

---

## 2. Giải Thích Luồng Xử Lý Mã Nguồn (`phong_mouse.c`)

### Bước 2.1: Cướp đường nối tiếp của USB (The Hooking Interface)

Làm sao Hệ điều hành biết cần phải "bàn giao" con chuột vật lý cho Driver `phong_mouse` của chúng ta điều hành, chứ không phải quăng vào xó nào khác? 
Ta định nghĩa một bảng ID khớp đúng mã chuẩn của chuột (USB_INTERFACE_PROTOCOL_MOUSE):

```c
/* Bảng ID nhận diện thiết bị đầu vào (Dành riêng cho Boot Protocol Mouse) */
static struct usb_device_id phong_mouse_id_table[] = {
    { USB_INTERFACE_INFO(USB_INTERFACE_CLASS_HID, USB_INTERFACE_SUBCLASS_BOOT, USB_INTERFACE_PROTOCOL_MOUSE) },
    { } /* Cờ hiệu kết thúc */
};
MODULE_DEVICE_TABLE(usb, phong_mouse_id_table);
```

### Bước 2.2: Khai báo đa tính năng (Mouse + Keyboard) ở hàm `Probe`
Ngay khi cắm chuột vào (hoặc khi driver được nạp chiếm quyền usbhid), Linux sẽ kích hoạt hàm `phong_mouse_probe`. Tại đây, Driver của chúng ta báo cáo lên Subsystem rằng "Tôi là chuột nhưng tôi có thể gõ phím".

```c
/* Khai báo tôi là thiết bị có mang Phím (EV_KEY) và Tọa độ (EV_REL) */
input_dev->evbit[0] = BIT_MASK(EV_KEY) | BIT_MASK(EV_REL);

/* Mảng thông tin Chuột (Trái, Phải, Giữa, Trục X Y, Lăn bánh xe) */
input_dev->keybit[BIT_WORD(BTN_MOUSE)] = BIT_MASK(BTN_LEFT) | BIT_MASK(BTN_RIGHT) | BIT_MASK(BTN_MIDDLE);
input_dev->relbit[0] = BIT_MASK(REL_X) | BIT_MASK(REL_Y) | BIT_MASK(REL_WHEEL);

/* Mảng thông tin Hacker (Xin phép được sờ vào các phím kí tự của bàn phím) */
set_bit(KEY_H, input_dev->keybit); // Nạp phím H
set_bit(KEY_E, input_dev->keybit); // Nạp phím E
// ... tiếp tục nhồi các phím L, O, P, SPACE
set_bit(KEY_LEFTSHIFT, input_dev->keybit); // Tổ hợp Phím Shift để in hoa
```

### Bước 2.3: Phân rã gói tín hiệu Chuột bằng URB Callback
Luồng dữ liệu chuột trỏ về máy tính liên tục với chu kì siêu thấp ~8ms bằng cấu trúc URB. Dữ liệu mộc nằm ở biến `mouse->data`, một mảng dài 4 tới 8 bytes tuỳ cấu trúc.
- `data[0]`: Gói Bit Mask các phím. (VD: Nhấn chuột phải thì data[0] bừng sáng các bit).
- `data[1] và [2]`: Toạ độ nhảy X/Y.

Hàm `phong_mouse_irq()` (Interrupt Request) sẽ móc túi thông điệp này:

```c
int left   = data[0] & 0x01; // Bit cuối (Trái)
int right  = data[0] & 0x02; // Áp chót (Phải)
int middle = data[0] & 0x04; // Bit thứ 3 (Chuột giữa = 0100)

/* NẾU LÀ CHUỘT GIỮA THÌ NUỐT CHỬNG SỰ KIỆN!!! */
if (middle) {
    if (!mouse->middle_btn_down) {
        mouse->middle_btn_down = 1; // Ngăn chặn bắn liên thanh (Debouncing)
        type_string_hello(dev);     // Điều hướng gọi hàm nhồi luồng mã phím
    }
} else {
    mouse->middle_btn_down = 0;
}

/* Các sự kiện khác Trái/Phải/Di chuột thì báo cáo gửi lên OS như bình thường (để dùng chuột mượt như thật) */
input_report_key(dev, BTN_LEFT,  left);
input_report_key(dev, BTN_RIGHT, right);
input_report_rel(dev, REL_X,     data[1]);
input_report_rel(dev, REL_Y,     data[2]);
```

### Bước 2.4: Đánh Lừa Tầng Nhập Văn Bản
Bất chấp con trỏ chuột không hề dính líu gì đến Bàn phím gõ bằng tay, hàm `type_string_hello()` ép input subsystem phải ghi nhận chuỗi thao tác vật lý bấm phím ảo cực tốc. 

Cấu trúc thao tác để gõ một chữ IN HOA (Ví dụ phím 'H'):
```c
static void type_char(struct input_dev *dev, unsigned int code, bool shift)
{
    /* BƯỚC 1: NHẤN TAY GIỮ LẤY NÚT SHIFT */
    if (shift) {
        input_report_key(dev, KEY_LEFTSHIFT, 1);
        input_sync(dev); // Lệnh input_sync chốt sổ ra lệnh: Hệ điều hành cập nhật trạng thái ngay!
    }
    
    /* BƯỚC 2: NHẤN XUỐNG PHÍM H */
    input_report_key(dev, code, 1);
    input_sync(dev);
    
    /* BƯỚC 3: NHẢ TAY KHỎI PHÍM H */
    input_report_key(dev, code, 0);
    input_sync(dev);

    /* BƯỚC 4: RỜI TAY KHỎI NÚT SHIFT */
    if (shift) {
        input_report_key(dev, KEY_LEFTSHIFT, 0);
        input_sync(dev);
    }
}
```
Lệnh `input_sync()` nhồi trạng thái "tức thì", khiến 4 thao tác trên tuy là tuần tự mã C nhưng thực tế được hệ thống ghi nhận gần như bọc kín trong cùng 1 frame xử lý. Do đó toàn bộ dòng chữ `Hello PhongPKF` chạy cực mượt mà và không thể bị gián đoạn hay kẹt phím ngoài.

---

## 3. Hướng Dẫn Biên Dịch Và Chạy (Bài 2)

Quá trình chạy driver chuột USB đòi hỏi bạn phải có chuột USB cắm ngoài thật và pass-through vào trong máy ảo VMware (Menu **VM** $\rightarrow$ **Removable Devices** $\rightarrow$ Chọn tên chuột $\rightarrow$ **Connect**).

### 3.1 Biên dịch Driver
Mở Terminal, đi vào thư mục bài 2:
```bash
cd ~/Desktop/bt-driver/bai2_usb_mouse
make clean
make
```

### 3.2 Nạp Script Đánh Tráo Chuột
Thay vì ngồi gõ lệnh dỡ và cài Module thủ công, tôi đã chuẩn bị sẵn file `load.sh`. Chạy file này để ép nhấc toàn bộ chuột đang trỏ vào máy tính chuyển sang Driver của chúng ta:
```bash
# Cấp quyền thực thi nếu chưa có
chmod +x load.sh

# Chạy kịch bản
sudo ./load.sh
```

### 3.3 Cách Test Hoạt Động
- Mở Terminal hoặc một ứng dụng Gedit / Text Editor lên.
- **Dùng chuột**: Click thử chuột Trái, Phải, di chuyển vòng quanh $\rightarrow$ Mọi thứ vẫn linh hoạt và mượt mà.
- Khai mở sức mạnh: Chĩa con trỏ chuột vào vùng nhập văn bản, **Nhấn con lăn chuột (Middle Click)**. 
- Màn hình sẽ ngay lập tức tuôn ra dòng chữ `Hello PhongPKF`.

### 3.4 Gỡ Bỏ Và Trả Lại Chuột Cho Máy
Sau khi test bài tập xong, bạn dọn dẹp bằng lệnh sau để xoá module Hack ra khỏi bộ nhớ và nhường lại quyền cho hệ điều hành kiểm soát:
```bash
sudo rmmod phong_mouse
sudo modprobe usbhid
```
