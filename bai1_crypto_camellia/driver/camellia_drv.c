// SPDX-License-Identifier: GPL-2.0
/*
 * camellia_drv.c - Kernel driver mã hóa file dùng thuật toán CAMELLIA
 *
 * Bài tập lớn - Lập trình Driver
 * Thuật toán: CAMELLIA-CBC 128-bit (via Linux Crypto API)
 *
 * Cách sử dụng:
 *   write(fd, data, len)         - ghi plaintext/ciphertext vào buffer
 *   ioctl(fd, CAMELLIA_ENCRYPT)  - mã hóa buffer
 *   ioctl(fd, CAMELLIA_DECRYPT)  - giải mã buffer
 *   ioctl(fd, CAMELLIA_GET_LEN)  - lấy kích thước dữ liệu sau xử lý
 *   read(fd, out, len)           - đọc kết quả ra
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#include "camellia_drv.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SinhVien");
MODULE_DESCRIPTION("CAMELLIA File Encryption Driver");
MODULE_VERSION("1.0");

#define DEVICE_NAME  "camellia_drv"
#define CLASS_NAME   "camellia"
#define MAX_BUF_SIZE (16 * 1024 * 1024)   /* 16 MB tối đa */

/* ===== Biến toàn cục ===== */
static int              major_number;
static struct class    *camellia_class  = NULL;
static struct device   *camellia_device = NULL;
static DEFINE_MUTEX(camellia_mutex);

/* Per-open-file state */
struct camellia_state {
    u8    *in_buf;      /* buffer nhận data từ write() */
    size_t in_len;      /* số byte đã write vào */
    u8    *out_buf;     /* buffer kết quả sau encrypt/decrypt */
    size_t out_len;     /* kích thước kết quả */
};

/* ===== Hàm mã hóa/giải mã core ===== */

/**
 * camellia_do_crypt - thực hiện mã hóa hoặc giải mã bằng CAMELLIA-CBC
 * @encrypt:    true = encrypt, false = decrypt
 * @key:        con trỏ khóa 16 bytes
 * @iv:         con trỏ IV 16 bytes (sẽ bị thay đổi, cần copy trước)
 * @in:         dữ liệu đầu vào
 * @in_len:     kích thước đầu vào (phải là bội số 16 khi decrypt)
 * @out:        buffer đầu ra (caller cấp phát)
 * @out_len:    kết quả: số byte thực sự ghi vào out
 *
 * Return: 0 nếu thành công, errno âm nếu lỗi
 */
static int camellia_do_crypt(bool encrypt,
                              const u8 *key, u8 *iv,
                              const u8 *in, size_t in_len,
                              u8 *out, size_t *out_len)
{
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_in, sg_out;
    u8 *padded_in = NULL;
    size_t padded_len;
    int ret;

    /* --- Tính padded length (PKCS#7) --- */
    if (encrypt) {
        /* Thêm padding sao cho là bội số của 16 */
        padded_len = ((in_len + CAMELLIA_BLOCK_SIZE) / CAMELLIA_BLOCK_SIZE)
                     * CAMELLIA_BLOCK_SIZE;
    } else {
        /* Khi decrypt, in_len phải đã là bội số 16 */
        if (in_len % CAMELLIA_BLOCK_SIZE != 0) {
            pr_err("camellia_drv: decrypt input không phải bội số 16\n");
            return -EINVAL;
        }
        padded_len = in_len;
    }

    /* --- Cấp buffer có padding --- */
    padded_in = kmalloc(padded_len, GFP_KERNEL);
    if (!padded_in)
        return -ENOMEM;

    memcpy(padded_in, in, in_len);

    if (encrypt) {
        /* Thêm PKCS#7 padding */
        u8 pad_val = (u8)(padded_len - in_len);
        memset(padded_in + in_len, pad_val, pad_val);
        pr_info("camellia_drv: encrypt %zu bytes → padded %zu bytes (pad=%u)\n",
                in_len, padded_len, pad_val);
    }

    /* --- Cấp phát cipher transform --- */
    tfm = crypto_alloc_skcipher("cbc(camellia)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("camellia_drv: không thể cấp phát cipher (lỗi %ld). "
               "Hãy chạy: sudo modprobe camellia_generic\n", PTR_ERR(tfm));
        ret = PTR_ERR(tfm);
        goto err_free_padded;
    }

    /* --- Set key --- */
    ret = crypto_skcipher_setkey(tfm, key, CAMELLIA_KEY_SIZE);
    if (ret) {
        pr_err("camellia_drv: setkey thất bại (%d)\n", ret);
        goto err_free_tfm;
    }

    /* --- Cấp phát request --- */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto err_free_tfm;
    }

    /* --- Chuẩn bị scatter-gather --- */
    sg_init_one(&sg_in,  padded_in, padded_len);
    sg_init_one(&sg_out, out,       padded_len);

    skcipher_request_set_crypt(req, &sg_in, &sg_out, padded_len, iv);

    /* --- Thực hiện crypto --- */
    if (encrypt)
        ret = crypto_skcipher_encrypt(req);
    else
        ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("camellia_drv: crypto thất bại (%d)\n", ret);
        goto err_free_req;
    }

    /* --- Tính out_len --- */
    if (encrypt) {
        *out_len = padded_len;
    } else {
        /* Xóa PKCS#7 padding */
        u8 pad = out[padded_len - 1];
        if (pad == 0 || pad > CAMELLIA_BLOCK_SIZE) {
            pr_err("camellia_drv: padding không hợp lệ: %u\n", pad);
            ret = -EBADMSG;
            goto err_free_req;
        }
        *out_len = padded_len - pad;
        pr_info("camellia_drv: decrypt %zu bytes → %zu bytes (pad=%u)\n",
                padded_len, *out_len, pad);
    }

    ret = 0;

err_free_req:
    skcipher_request_free(req);
err_free_tfm:
    crypto_free_skcipher(tfm);
err_free_padded:
    kfree(padded_in);
    return ret;
}

/* ===== File operations ===== */

static int dev_open(struct inode *inodep, struct file *filep)
{
    struct camellia_state *state;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return -ENOMEM;

    filep->private_data = state;
    pr_info("camellia_drv: device opened\n");
    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
    struct camellia_state *state = filep->private_data;

    if (state) {
        kfree(state->in_buf);
        kfree(state->out_buf);
        kfree(state);
    }
    pr_info("camellia_drv: device closed\n");
    return 0;
}

/**
 * dev_write - nhận dữ liệu từ userspace, lưu vào in_buf
 * Userspace gọi write() để gửi plaintext (khi encrypt) hoặc ciphertext (khi decrypt)
 */
static ssize_t dev_write(struct file *filep, const char __user *buffer,
                          size_t len, loff_t *offset)
{
    struct camellia_state *state = filep->private_data;

    if (len == 0 || len > MAX_BUF_SIZE)
        return -EINVAL;

    mutex_lock(&camellia_mutex);

    /* Giải phóng buffer cũ nếu có */
    kfree(state->in_buf);
    kfree(state->out_buf);
    state->out_buf = NULL;
    state->out_len = 0;

    state->in_buf = kmalloc(len, GFP_KERNEL);
    if (!state->in_buf) {
        mutex_unlock(&camellia_mutex);
        return -ENOMEM;
    }

    if (copy_from_user(state->in_buf, buffer, len)) {
        kfree(state->in_buf);
        state->in_buf = NULL;
        mutex_unlock(&camellia_mutex);
        return -EFAULT;
    }

    state->in_len = len;
    pr_info("camellia_drv: nhận %zu bytes từ userspace\n", len);

    mutex_unlock(&camellia_mutex);
    return len;
}

/**
 * dev_read - trả kết quả sau encrypt/decrypt về userspace
 */
static ssize_t dev_read(struct file *filep, char __user *buffer,
                         size_t len, loff_t *offset)
{
    struct camellia_state *state = filep->private_data;
    size_t to_copy;

    mutex_lock(&camellia_mutex);

    if (!state->out_buf || state->out_len == 0) {
        mutex_unlock(&camellia_mutex);
        return -ENODATA;
    }

    if (*offset >= state->out_len) {
        mutex_unlock(&camellia_mutex);
        return 0;
    }

    to_copy = min(len, state->out_len - (size_t)*offset);

    if (copy_to_user(buffer, state->out_buf + *offset, to_copy)) {
        mutex_unlock(&camellia_mutex);
        return -EFAULT;
    }

    *offset += to_copy;
    pr_info("camellia_drv: gửi %zu bytes về userspace\n", to_copy);

    mutex_unlock(&camellia_mutex);
    return to_copy;
}

/**
 * dev_ioctl - xử lý lệnh encrypt/decrypt/get_len
 */
static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    struct camellia_state *state = filep->private_data;
    struct camellia_params params;
    size_t out_size;
    int ret;

    if (_IOC_TYPE(cmd) != CAMELLIA_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > CAMELLIA_IOC_MAXNR)
        return -ENOTTY;

    switch (cmd) {
    case CAMELLIA_ENCRYPT:
    case CAMELLIA_DECRYPT:
        if (copy_from_user(&params, (struct camellia_params __user *)arg,
                           sizeof(params)))
            return -EFAULT;

        if (!state->in_buf || state->in_len == 0) {
            pr_err("camellia_drv: chưa có dữ liệu (gọi write() trước)\n");
            return -ENODATA;
        }

        mutex_lock(&camellia_mutex);

        /* Cấp phát output buffer (thêm 1 block dự phòng) */
        out_size = state->in_len + CAMELLIA_BLOCK_SIZE;
        kfree(state->out_buf);
        state->out_buf = kzalloc(out_size, GFP_KERNEL);
        if (!state->out_buf) {
            mutex_unlock(&camellia_mutex);
            return -ENOMEM;
        }

        ret = camellia_do_crypt(
            (cmd == CAMELLIA_ENCRYPT),
            params.key,
            params.iv,
            state->in_buf,
            state->in_len,
            state->out_buf,
            &state->out_len
        );

        if (ret) {
            kfree(state->out_buf);
            state->out_buf = NULL;
            state->out_len = 0;
            mutex_unlock(&camellia_mutex);
            return ret;
        }

        /* Reset read offset */
        filep->f_pos = 0;
        mutex_unlock(&camellia_mutex);
        return 0;

    case CAMELLIA_GET_LEN:
        mutex_lock(&camellia_mutex);
        if (copy_to_user((size_t __user *)arg, &state->out_len,
                         sizeof(size_t))) {
            mutex_unlock(&camellia_mutex);
            return -EFAULT;
        }
        mutex_unlock(&camellia_mutex);
        return 0;

    default:
        return -ENOTTY;
    }
}

/* ===== File operations struct ===== */
static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = dev_open,
    .release        = dev_release,
    .read           = dev_read,
    .write          = dev_write,
    .unlocked_ioctl = dev_ioctl,
};

/* ===== Module init/exit ===== */
static char *camellia_devnode(const struct device *dev, umode_t *mode)
{
    if (mode)
        *mode = 0666;
    return NULL;
}

static int __init camellia_init(void)
{
    pr_info("camellia_drv: đang khởi tạo...\n");

    /* Yêu cầu kernel load camellia_generic nếu chưa có */
    request_module("camellia_generic");

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("camellia_drv: register_chrdev thất bại (%d)\n", major_number);
        return major_number;
    }

    camellia_class = class_create(CLASS_NAME);
    if (IS_ERR(camellia_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(camellia_class);
    }
    camellia_class->devnode = camellia_devnode;

    camellia_device = device_create(camellia_class, NULL,
                                    MKDEV(major_number, 0),
                                    NULL, DEVICE_NAME);
    if (IS_ERR(camellia_device)) {
        class_destroy(camellia_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(camellia_device);
    }

    pr_info("camellia_drv: sẵn sàng tại /dev/%s (major=%d)\n",
            DEVICE_NAME, major_number);
    return 0;
}

static void __exit camellia_exit(void)
{
    device_destroy(camellia_class, MKDEV(major_number, 0));
    class_unregister(camellia_class);
    class_destroy(camellia_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    pr_info("camellia_drv: đã gỡ tải\n");
}

module_init(camellia_init);
module_exit(camellia_exit);
