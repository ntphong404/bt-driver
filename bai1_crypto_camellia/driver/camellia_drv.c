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
#include <linux/vmalloc.h>

#include "camellia_drv.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SinhVien");
MODULE_DESCRIPTION("CAMELLIA File Encryption Driver");
MODULE_VERSION("1.0");

#define DEVICE_NAME  "camellia_drv"
#define CLASS_NAME   "camellia"
#define MAX_BUF_SIZE (16 * 1024 * 1024)   /* 16 MB tối đa */

/*
 * Kích thước mỗi chunk khi xử lý crypto.
 * Dùng chunk nhỏ (256 KB) để scatterlist luôn dùng kmalloc (liên tục vật lý)
 * → tương thích hoàn hảo với sg_init_one().
 * CBC mode tự cập nhật IV sau mỗi chunk nên kết quả giống hệt xử lý một lần.
 */
#define CRYPT_CHUNK_SIZE (256 * 1024)

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
 * @iv:         con trỏ IV 16 bytes (sẽ bị thay đổi sau mỗi chunk - CBC chaining)
 * @in:         dữ liệu đầu vào (có thể là vmalloc'd)
 * @in_len:     kích thước đầu vào (phải là bội số 16 khi decrypt)
 * @out:        buffer đầu ra (có thể là vmalloc'd, caller cấp phát)
 * @out_len:    kết quả: số byte thực sự ghi vào out
 *
 * Xử lý theo chunk nhỏ (CRYPT_CHUNK_SIZE) để tránh kmalloc lớn cho scatterlist.
 * IV được crypto API tự cập nhật sau mỗi chunk (CBC mode chaining).
 *
 * Return: 0 nếu thành công, errno âm nếu lỗi
 */
static int camellia_do_crypt(bool encrypt,
                              const u8 *key, u8 *iv,
                              const u8 *in, size_t in_len,
                              u8 *out, size_t *out_len)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg_in, sg_out;
    u8 *padded_in = NULL;
    u8 *chunk_in = NULL, *chunk_out = NULL;
    size_t padded_len, chunk_size;
    size_t offset;
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

    /* --- Cấp buffer có padding (kvmalloc hỗ trợ file lớn) --- */
    padded_in = kvmalloc(padded_len, GFP_KERNEL);
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
        tfm = NULL;
        goto err_cleanup;
    }

    /* --- Set key --- */
    ret = crypto_skcipher_setkey(tfm, key, CAMELLIA_KEY_SIZE);
    if (ret) {
        pr_err("camellia_drv: setkey thất bại (%d)\n", ret);
        goto err_cleanup;
    }

    /* --- Cấp phát request --- */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto err_cleanup;
    }

    /* --- Cấp chunk buffer (kmalloc nhỏ, luôn liên tục vật lý) --- */
    chunk_size = min((size_t)CRYPT_CHUNK_SIZE, padded_len);
    chunk_in = kmalloc(chunk_size, GFP_KERNEL);
    chunk_out = kmalloc(chunk_size, GFP_KERNEL);
    if (!chunk_in || !chunk_out) {
        ret = -ENOMEM;
        goto err_cleanup;
    }

    /* --- Xử lý crypto theo từng chunk --- */
    /*
     * CBC mode: sau mỗi lần gọi crypto_skcipher_encrypt/decrypt,
     * crypto API tự cập nhật IV (truyền qua con trỏ iv) thành
     * block ciphertext cuối cùng → chunk tiếp theo dùng đúng IV.
     */
    offset = 0;
    while (offset < padded_len) {
        size_t this_chunk = min(chunk_size, padded_len - offset);

        /* Copy từ padded_in (có thể vmalloc) → chunk_in (kmalloc) */
        memcpy(chunk_in, padded_in + offset, this_chunk);

        sg_init_one(&sg_in,  chunk_in,  this_chunk);
        sg_init_one(&sg_out, chunk_out, this_chunk);

        skcipher_request_set_crypt(req, &sg_in, &sg_out, this_chunk, iv);

        if (encrypt)
            ret = crypto_skcipher_encrypt(req);
        else
            ret = crypto_skcipher_decrypt(req);

        if (ret) {
            pr_err("camellia_drv: crypto thất bại ở offset %zu (%d)\n",
                   offset, ret);
            goto err_cleanup;
        }

        /* Copy kết quả từ chunk_out (kmalloc) → out (có thể vmalloc) */
        memcpy(out + offset, chunk_out, this_chunk);

        offset += this_chunk;
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
            goto err_cleanup;
        }
        *out_len = padded_len - pad;
        pr_info("camellia_drv: decrypt %zu bytes → %zu bytes (pad=%u)\n",
                padded_len, *out_len, pad);
    }

    ret = 0;

err_cleanup:
    kfree(chunk_out);
    kfree(chunk_in);
    if (req)
        skcipher_request_free(req);
    if (tfm)
        crypto_free_skcipher(tfm);
    kvfree(padded_in);
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
        kvfree(state->in_buf);
        kvfree(state->out_buf);
        kfree(state);
    }
    pr_info("camellia_drv: device closed\n");
    return 0;
}

/**
 * dev_write - nhận dữ liệu từ userspace, lưu vào in_buf
 * Userspace gọi write() để gửi plaintext (khi encrypt) hoặc ciphertext (khi decrypt)
 *
 * Sử dụng kvmalloc thay vì kmalloc để hỗ trợ file lớn (>4 MB).
 * kvmalloc sẽ thử kmalloc trước, nếu thất bại sẽ chuyển sang vmalloc.
 */
static ssize_t dev_write(struct file *filep, const char __user *buffer,
                          size_t len, loff_t *offset)
{
    struct camellia_state *state = filep->private_data;

    if (len == 0 || len > MAX_BUF_SIZE)
        return -EINVAL;

    mutex_lock(&camellia_mutex);

    /* Giải phóng buffer cũ nếu có */
    kvfree(state->in_buf);
    kvfree(state->out_buf);
    state->out_buf = NULL;
    state->out_len = 0;

    state->in_buf = kvmalloc(len, GFP_KERNEL);
    if (!state->in_buf) {
        mutex_unlock(&camellia_mutex);
        return -ENOMEM;
    }

    if (copy_from_user(state->in_buf, buffer, len)) {
        kvfree(state->in_buf);
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
 *
 * Output buffer dùng kvzalloc để hỗ trợ file lớn.
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
        kvfree(state->out_buf);
        state->out_buf = kvzalloc(out_size, GFP_KERNEL);
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
            kvfree(state->out_buf);
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
    .llseek         = default_llseek,
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
