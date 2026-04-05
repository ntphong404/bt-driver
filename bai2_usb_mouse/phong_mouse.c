// SPDX-License-Identifier: GPL-2.0
/**
 * phong_mouse.c - Driver "Hack" chuột USB báo cáo phím ảo
 * 
 * Bài 2 - Lập trình Driver
 * Mục tiêu: Bắt sự kiện chuột giữa (Middle click). Thay vì gửi click chuột,
 * driver giả lập gửi chuỗi sự kiện độ trễ thấp sinh ra phím "Hello PhongPKF\n".
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/usb/input.h>
#include <linux/hid.h>

#define DRIVER_VERSION "1.0"
#define DRIVER_AUTHOR "PhongPKF"
#define DRIVER_DESC "USB Mouse Hack Driver - Hello PhongPKF"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION(DRIVER_VERSION);

struct phong_mouse {
    char name[128];
    char phys[64];
    struct usb_device *usbdev;
    struct input_dev *dev;
    struct urb *irq;

    signed char *data;
    dma_addr_t data_dma;
    
    int middle_btn_down;
};

/* ===== Tiện ích gửi từng ký tự ===== */
static void type_char(struct input_dev *dev, unsigned int code, bool shift)
{
    if (shift) {
        input_report_key(dev, KEY_LEFTSHIFT, 1);
        input_sync(dev);
    }
    
    /* Nhấn phím */
    input_report_key(dev, code, 1);
    input_sync(dev);
    
    /* Nhả phím */
    input_report_key(dev, code, 0);
    input_sync(dev);

    if (shift) {
        input_report_key(dev, KEY_LEFTSHIFT, 0);
        input_sync(dev);
    }
}

/* ===== Giả lập gõ chữ "Hello PhongPKF\n" ===== */
static void type_string_hello(struct input_dev *dev)
{
    type_char(dev, KEY_H, true);
    type_char(dev, KEY_E, false);
    type_char(dev, KEY_L, false);
    type_char(dev, KEY_L, false);
    type_char(dev, KEY_O, false);
    type_char(dev, KEY_SPACE, false);
    
    type_char(dev, KEY_P, true);
    type_char(dev, KEY_H, false);
    type_char(dev, KEY_O, false);
    type_char(dev, KEY_N, false);
    type_char(dev, KEY_G, false);
    
    type_char(dev, KEY_P, true);
    type_char(dev, KEY_K, true);
    type_char(dev, KEY_F, true);
}

/* ===== Trình xử lý ngắt (khi chuột bị di chuyển / nhấn nút) ===== */
static void phong_mouse_irq(struct urb *urb)
{
    struct phong_mouse *mouse = urb->context;
    signed char *data = mouse->data;
    struct input_dev *dev = mouse->dev;
    int status;

    switch (urb->status) {
    case 0:         /* success */
        break;
    case -ECONNRESET:   /* unlink */
    case -ENOENT:
    case -ESHUTDOWN:
        return; /* -EPIPE:  nên dọn dẹp (tạm bỏ qua để đơn giản hóa) */
    default:        /* error */
        goto resubmit;
    }

    /* Đữ liệu chuẩn của Boot Protocol Mouse 
       data[0]: Trạng thái nút (Bit 0: Left, 1: Right, 2: Middle)
       data[1]: X
       data[2]: Y
       data[3]: Wheel scroll
    */
    int left   = data[0] & 0x01;
    int right  = data[0] & 0x02;
    int middle = data[0] & 0x04;

    /* PHẦN HACK MOUSE BẮT SỰ KIỆN MIDDLE CLICK */
    if (middle) {
        if (!mouse->middle_btn_down) {
            mouse->middle_btn_down = 1;
            pr_info("phong_mouse: Phat hien Middle click! Go phim tu dong...\n");
            type_string_hello(dev);
        }
    } else {
        mouse->middle_btn_down = 0;
    }

    /* Báo cáo trạng thái chuột bình thường (ko báo cáo nút Middle ra OS) */
    input_report_key(dev, BTN_LEFT,  left);
    input_report_key(dev, BTN_RIGHT, right);

    input_report_rel(dev, REL_X,     data[1]);
    input_report_rel(dev, REL_Y,     data[2]);
    input_report_rel(dev, REL_WHEEL, data[3]);

    input_sync(dev);

resubmit:
    status = usb_submit_urb(urb, GFP_ATOMIC);
    if (status)
        dev_err(&mouse->usbdev->dev, "cannot resubmit urb, err %d\n", status);
}

static int phong_mouse_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(intf);
    struct usb_endpoint_descriptor *endpoint;
    struct phong_mouse *mouse;
    struct input_dev *input_dev;
    int pipe, maxp;
    int error = -ENOMEM;

    if (intf->cur_altsetting->desc.bNumEndpoints != 1)
        return -ENODEV;

    endpoint = &intf->cur_altsetting->endpoint[0].desc;
    if (!usb_endpoint_is_int_in(endpoint))
        return -ENODEV;

    pipe = usb_rcvintpipe(dev, endpoint->bEndpointAddress);
    maxp = usb_maxpacket(dev, pipe);

    mouse = kzalloc(sizeof(*mouse), GFP_KERNEL);
    input_dev = input_allocate_device();
    if (!mouse || !input_dev)
        goto fail1;

    mouse->data = usb_alloc_coherent(dev, 8, GFP_KERNEL, &mouse->data_dma);
    if (!mouse->data)
        goto fail1;

    mouse->irq = usb_alloc_urb(0, GFP_KERNEL);
    if (!mouse->irq)
        goto fail2;

    mouse->usbdev = dev;
    mouse->dev = input_dev;

    snprintf(mouse->name, sizeof(mouse->name), "PhongPKF Hack Mouse %04x:%04x",
             le16_to_cpu(dev->descriptor.idVendor), le16_to_cpu(dev->descriptor.idProduct));

    usb_make_path(dev, mouse->phys, sizeof(mouse->phys));
    snprintf(mouse->phys + strlen(mouse->phys), sizeof(mouse->phys) - strlen(mouse->phys), "/input0");

    input_dev->name = mouse->name;
    input_dev->phys = mouse->phys;
    usb_to_input_id(dev, &input_dev->id);
    input_dev->dev.parent = &intf->dev;

    /* Cấu hình hỗ trợ Input Device (Virtual Keyboard + Mouse) */
    input_dev->evbit[0] = BIT_MASK(EV_KEY) | BIT_MASK(EV_REL);
    
    // Thuộc tính Mouse
    input_dev->keybit[BIT_WORD(BTN_MOUSE)] = BIT_MASK(BTN_LEFT) | BIT_MASK(BTN_RIGHT) | BIT_MASK(BTN_MIDDLE);
    input_dev->relbit[0] = BIT_MASK(REL_X) | BIT_MASK(REL_Y) | BIT_MASK(REL_WHEEL);

    // Thuộc tính Keyboard (các phím được phép giả lập)
    set_bit(KEY_H, input_dev->keybit);
    set_bit(KEY_E, input_dev->keybit);
    set_bit(KEY_L, input_dev->keybit);
    set_bit(KEY_O, input_dev->keybit);
    set_bit(KEY_SPACE, input_dev->keybit);
    set_bit(KEY_P, input_dev->keybit);
    set_bit(KEY_N, input_dev->keybit);
    set_bit(KEY_G, input_dev->keybit);
    set_bit(KEY_K, input_dev->keybit);
    set_bit(KEY_F, input_dev->keybit);
    set_bit(KEY_ENTER, input_dev->keybit);
    set_bit(KEY_LEFTSHIFT, input_dev->keybit);

    input_set_drvdata(input_dev, mouse);

    usb_fill_int_urb(mouse->irq, dev, pipe, mouse->data,
             (maxp > 8 ? 8 : maxp),
             phong_mouse_irq, mouse, endpoint->bInterval);
    mouse->irq->transfer_dma = mouse->data_dma;
    mouse->irq->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

    error = input_register_device(mouse->dev);
    if (error)
        goto fail3;

    usb_set_intfdata(intf, mouse);

    /* Submit URB để bắt đầu liên tục lắng nghe Mouse interrupts */
    if (usb_submit_urb(mouse->irq, GFP_KERNEL)) {
        pr_err("phong_mouse: Khong the the submit urb ngat!\n");
        goto fail4;
    }

    pr_info("phong_mouse: Driver da gan chuot! Hay click thu banh xe / Middle click nhe.\n");
    return 0;

fail4:
    input_unregister_device(mouse->dev);
    mouse->dev = NULL;
fail3:  
    usb_free_urb(mouse->irq);
fail2:  
    usb_free_coherent(dev, 8, mouse->data, mouse->data_dma);
fail1:  
    if (mouse && mouse->dev)
        input_free_device(input_dev);
    kfree(mouse);
    return error;
}

static void phong_mouse_disconnect(struct usb_interface *intf)
{
    struct phong_mouse *mouse = usb_get_intfdata(intf);

    usb_set_intfdata(intf, NULL);
    if (mouse) {
        usb_kill_urb(mouse->irq);
        input_unregister_device(mouse->dev);
        usb_free_urb(mouse->irq);
        usb_free_coherent(interface_to_usbdev(intf), 8, mouse->data, mouse->data_dma);
        kfree(mouse);
        pr_info("phong_mouse: Da go chuot.\n");
    }
}

/* Đăng ký device id_table. Chỉ match HID class => boot protocol mouse */
static struct usb_device_id phong_mouse_id_table[] = {
    { USB_INTERFACE_INFO(USB_INTERFACE_CLASS_HID, USB_INTERFACE_SUBCLASS_BOOT, USB_INTERFACE_PROTOCOL_MOUSE) },
    { } /* Cờ hiệu kết thúc */
};

MODULE_DEVICE_TABLE(usb, phong_mouse_id_table);

static struct usb_driver phong_mouse_driver = {
    .name       = "phong_mouse",
    .probe      = phong_mouse_probe,
    .disconnect = phong_mouse_disconnect,
    .id_table   = phong_mouse_id_table,
};

module_usb_driver(phong_mouse_driver);
