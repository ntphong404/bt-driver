#!/bin/bash

echo "=== Dọn dẹp module nếu đang chạy ==="
sudo rmmod phong_mouse 2>/dev/null

echo "=== Cài đặt phong_mouse ==="
# Để thiết bị lấy phong_mouse làm driver (thay vì mặc định là usbhid), 
# ta sẽ tạm thời dỡ usbhid (có thể làm bàn phím khựng vài giây),
# tải phong_mouse, sau đó ngay lập tức khôi phục usbhid.
sudo sh -c "rmmod usbhid 2>/dev/null; insmod phong_mouse.ko; modprobe usbhid"

echo "=== Đã tải Driver Hack phong_mouse ==="
echo "Kiểm tra log bằng lệnh: dmesg | tail -n 10"
echo "Bạn có thể test bằng cách nhấn chuột giữa ngay bây giờ!"
