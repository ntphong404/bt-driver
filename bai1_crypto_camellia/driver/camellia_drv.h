#ifndef CAMELLIA_DRV_H
#define CAMELLIA_DRV_H

#include <linux/ioctl.h>

#define CAMELLIA_IOC_MAGIC  'K'
#define CAMELLIA_KEY_SIZE   16   /* 128-bit key */
#define CAMELLIA_BLOCK_SIZE 16   /* CAMELLIA block size */

/**
 * struct camellia_params - tham số truyền qua IOCTL
 * @key: khóa mã hóa 16 bytes (128-bit)
 * @iv:  initialization vector 16 bytes (CBC mode)
 */
struct camellia_params {
    unsigned char key[CAMELLIA_KEY_SIZE];
    unsigned char iv[CAMELLIA_KEY_SIZE];
};

/* IOCTL commands */
#define CAMELLIA_ENCRYPT  _IOW(CAMELLIA_IOC_MAGIC, 1, struct camellia_params)
#define CAMELLIA_DECRYPT  _IOW(CAMELLIA_IOC_MAGIC, 2, struct camellia_params)
#define CAMELLIA_GET_LEN  _IOR(CAMELLIA_IOC_MAGIC, 3, size_t)

#define CAMELLIA_IOC_MAXNR 3

#endif /* CAMELLIA_DRV_H */
