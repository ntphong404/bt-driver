/*
 * file_manager.c - Chương trình quản lý file bảo mật dùng CAMELLIA driver
 *
 * Bài tập lớn - Lập trình Driver
 *
 * Cách dùng:
 *   ./file_manager encrypt <file>          - Mã hóa file → <file>.enc
 *   ./file_manager decrypt <file.enc>      - Giải mã file.enc → file gốc
 *   ./file_manager list [thư_mục]          - Liệt kê file .enc
 *   ./file_manager view <file.enc>         - Xem nội dung sau giải mã
 *
 * Định dạng file .enc:
 *   [4B] magic = "CAMF"
 *   [4B] kích thước file gốc (uint32_t)
 *   [16B] IV (Initialization Vector)
 *   [NB] ciphertext (đã padded, N = ceil(size/16)*16)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

/* Header chung với driver */
#include "../driver/camellia_drv.h"

/* ===== Cấu hình ===== */
#define DEVICE_PATH     "/dev/camellia_drv"
#define ENC_MAGIC       "CAMF"
#define ENC_MAGIC_LEN   4
#define ENC_EXTENSION   ".enc"

/* Mặc định: key cố định để demo (trong thực tế nên nhập từ bàn phím/file) */
static const unsigned char DEFAULT_KEY[CAMELLIA_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

/* ===== Header file .enc ===== */
#pragma pack(1)
struct enc_header {
    char     magic[ENC_MAGIC_LEN];  /* "CAMF" */
    uint32_t orig_size;             /* kích thước file gốc */
    uint8_t  iv[CAMELLIA_KEY_SIZE]; /* IV ngẫu nhiên */
};
#pragma pack()

/* ===== Tiện ích ===== */

static void print_usage(const char *prog)
{
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   🔐 File Manager - CAMELLIA Encryption  ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    printf("Cách dùng:\n");
    printf("  %s encrypt <file>        - Mã hóa file\n", prog);
    printf("  %s decrypt <file.enc>    - Giải mã file\n", prog);
    printf("  %s list [thư_mục]        - Liệt kê file đã mã hóa\n", prog);
    printf("  %s view <file.enc>       - Xem nội dung file (text)\n\n", prog);
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 8; i++)
        printf("%02X ", data[i]);
    printf("...\n");
}

/** Đọc toàn bộ file vào bộ nhớ */
static uint8_t *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "❌ Không mở được file: %s (%s)\n", path, strerror(errno));
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fprintf(stderr, "❌ File rỗng hoặc lỗi: %s\n", path);
        fclose(f);
        return NULL;
    }

    uint8_t *buf = malloc(sz);
    if (!buf) {
        fprintf(stderr, "❌ Không đủ bộ nhớ\n");
        fclose(f);
        return NULL;
    }

    if ((long)fread(buf, 1, sz, f) != sz) {
        fprintf(stderr, "❌ Đọc file thất bại: %s\n", path);
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

/** Sinh IV ngẫu nhiên từ /dev/urandom */
static int gen_random_iv(uint8_t *iv, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Fallback nếu không mở được */
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < len; i++)
            iv[i] = (uint8_t)(rand() & 0xFF);
        return 0;
    }
    ssize_t n = read(fd, iv, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/** Tính kích thước ciphertext (padded) */
static size_t padded_size(size_t plain_len)
{
    return ((plain_len + CAMELLIA_BLOCK_SIZE) / CAMELLIA_BLOCK_SIZE)
           * CAMELLIA_BLOCK_SIZE;
}

/* ===== Tương tác với driver ===== */

/**
 * driver_encrypt - gửi plaintext lên driver, nhận ciphertext về
 * @plain:     dữ liệu gốc
 * @plain_len: kích thước dữ liệu gốc
 * @key:       khóa 16 bytes
 * @iv:        IV 16 bytes
 * @out_len:   [output] kích thước ciphertext
 * Return: buffer ciphertext (caller free()), hoặc NULL nếu lỗi
 */
static uint8_t *driver_encrypt(const uint8_t *plain, size_t plain_len,
                                const uint8_t *key, const uint8_t *iv,
                                size_t *out_len)
{
    struct camellia_params params;
    size_t enc_size = padded_size(plain_len);
    uint8_t *cipher = NULL;
    int drv_fd;
    ssize_t n;

    drv_fd = open(DEVICE_PATH, O_RDWR);
    if (drv_fd < 0) {
        fprintf(stderr, "❌ Không mở được %s: %s\n  "
                "→ Kiểm tra: sudo insmod camellia_drv.ko\n",
                DEVICE_PATH, strerror(errno));
        return NULL;
    }

    /* Gửi plaintext vào driver */
    n = write(drv_fd, plain, plain_len);
    if (n != (ssize_t)plain_len) {
        fprintf(stderr, "❌ write() thất bại: %s\n", strerror(errno));
        goto err_close;
    }

    /* Chuẩn bị params IOCTL */
    memcpy(params.key, key, CAMELLIA_KEY_SIZE);
    memcpy(params.iv,  iv,  CAMELLIA_KEY_SIZE);

    /* Gọi IOCTL để mã hóa */
    if (ioctl(drv_fd, CAMELLIA_ENCRYPT, &params) < 0) {
        fprintf(stderr, "❌ ioctl ENCRYPT thất bại: %s\n", strerror(errno));
        goto err_close;
    }

    /* Lấy kích thước thực tế */
    if (ioctl(drv_fd, CAMELLIA_GET_LEN, &enc_size) < 0) {
        /* Fallback: dùng padded_size */
        enc_size = padded_size(plain_len);
    }

    /* Đọc ciphertext */
    cipher = malloc(enc_size);
    if (!cipher) {
        fprintf(stderr, "❌ malloc thất bại\n");
        goto err_close;
    }

    n = read(drv_fd, cipher, enc_size);
    if (n <= 0) {
        fprintf(stderr, "❌ read() thất bại: %s\n", strerror(errno));
        free(cipher);
        cipher = NULL;
        goto err_close;
    }

    *out_len = (size_t)n;

err_close:
    close(drv_fd);
    return cipher;
}

/**
 * driver_decrypt - gửi ciphertext lên driver, nhận plaintext về
 */
static uint8_t *driver_decrypt(const uint8_t *cipher, size_t cipher_len,
                                const uint8_t *key, const uint8_t *iv,
                                size_t *out_len)
{
    struct camellia_params params;
    uint8_t *plain = NULL;
    int drv_fd;
    ssize_t n;

    drv_fd = open(DEVICE_PATH, O_RDWR);
    if (drv_fd < 0) {
        fprintf(stderr, "❌ Không mở được %s: %s\n", DEVICE_PATH, strerror(errno));
        return NULL;
    }

    n = write(drv_fd, cipher, cipher_len);
    if (n != (ssize_t)cipher_len) {
        fprintf(stderr, "❌ write() thất bại: %s\n", strerror(errno));
        goto err_close;
    }

    memcpy(params.key, key, CAMELLIA_KEY_SIZE);
    memcpy(params.iv,  iv,  CAMELLIA_KEY_SIZE);

    if (ioctl(drv_fd, CAMELLIA_DECRYPT, &params) < 0) {
        fprintf(stderr, "❌ ioctl DECRYPT thất bại: %s\n", strerror(errno));
        goto err_close;
    }

    size_t dec_size = cipher_len; /* plaintext luôn <= ciphertext */
    if (ioctl(drv_fd, CAMELLIA_GET_LEN, &dec_size) < 0)
        dec_size = cipher_len;

    plain = malloc(dec_size + 1); /* +1 cho null-terminator khi view */
    if (!plain) goto err_close;

    n = read(drv_fd, plain, dec_size);
    if (n <= 0) {
        fprintf(stderr, "❌ read() thất bại: %s\n", strerror(errno));
        free(plain);
        plain = NULL;
        goto err_close;
    }

    plain[n] = '\0'; /* safe for text view */
    *out_len = (size_t)n;

err_close:
    close(drv_fd);
    return plain;
}

/* ===== Lệnh: encrypt ===== */
static int cmd_encrypt(const char *input_path)
{
    uint8_t *plain = NULL;
    uint8_t *cipher = NULL;
    size_t plain_len, cipher_len;
    struct enc_header hdr;
    uint8_t iv[CAMELLIA_KEY_SIZE];
    char out_path[512];
    FILE *fout = NULL;
    int ret = 0;

    printf("🔐 Đang mã hóa: %s\n", input_path);

    /* Đọc file gốc */
    plain = read_file(input_path, &plain_len);
    if (!plain) return 1;

    printf("   📄 Kích thước gốc: %zu bytes\n", plain_len);

    /* Sinh IV ngẫu nhiên */
    if (gen_random_iv(iv, sizeof(iv)) < 0) {
        fprintf(stderr, "❌ Không sinh được IV\n");
        ret = 1; goto done;
    }
    print_hex("   🔑 IV", iv, sizeof(iv));

    /* Mã hóa qua driver */
    cipher = driver_encrypt(plain, plain_len, DEFAULT_KEY, iv, &cipher_len);
    if (!cipher) { ret = 1; goto done; }

    printf("   🔒 Kích thước ciphertext: %zu bytes\n", cipher_len);

    /* Tạo đường dẫn output */
    snprintf(out_path, sizeof(out_path), "%s%s", input_path, ENC_EXTENSION);

    fout = fopen(out_path, "wb");
    if (!fout) {
        fprintf(stderr, "❌ Không tạo được file: %s\n", out_path);
        ret = 1; goto done;
    }

    /* Ghi header */
    memcpy(hdr.magic, ENC_MAGIC, ENC_MAGIC_LEN);
    hdr.orig_size = (uint32_t)plain_len;
    memcpy(hdr.iv, iv, CAMELLIA_KEY_SIZE);
    fwrite(&hdr, sizeof(hdr), 1, fout);

    /* Ghi ciphertext */
    fwrite(cipher, 1, cipher_len, fout);
    fclose(fout);
    fout = NULL;

    printf("   ✅ Đã lưu: %s\n", out_path);

done:
    free(plain);
    free(cipher);
    if (fout) fclose(fout);
    return ret;
}

/* ===== Lệnh: decrypt ===== */
static int cmd_decrypt(const char *enc_path)
{
    uint8_t *ciphertext = NULL;
    uint8_t *plaintext  = NULL;
    size_t file_size, cipher_len, plain_len;
    struct enc_header hdr;
    char out_path[512];
    FILE *fin  = NULL;
    FILE *fout = NULL;
    int ret = 0;

    printf("🔓 Đang giải mã: %s\n", enc_path);

    fin = fopen(enc_path, "rb");
    if (!fin) {
        fprintf(stderr, "❌ Không mở được: %s (%s)\n", enc_path, strerror(errno));
        return 1;
    }

    /* Đọc và kiểm tra header */
    if (fread(&hdr, sizeof(hdr), 1, fin) != 1) {
        fprintf(stderr, "❌ File quá nhỏ hoặc bị hỏng\n");
        ret = 1; goto done;
    }

    if (memcmp(hdr.magic, ENC_MAGIC, ENC_MAGIC_LEN) != 0) {
        fprintf(stderr, "❌ File không phải định dạng CAMF (sai magic bytes)\n");
        ret = 1; goto done;
    }

    /* Tính kích thước ciphertext */
    fseek(fin, 0, SEEK_END);
    file_size = (size_t)ftell(fin);
    cipher_len = file_size - sizeof(hdr);

    if (cipher_len == 0 || cipher_len % CAMELLIA_BLOCK_SIZE != 0) {
        fprintf(stderr, "❌ Ciphertext không hợp lệ (%zu bytes)\n", cipher_len);
        ret = 1; goto done;
    }

    /* Đọc ciphertext */
    fseek(fin, sizeof(hdr), SEEK_SET);
    ciphertext = malloc(cipher_len);
    if (!ciphertext) { ret = 1; goto done; }

    if (fread(ciphertext, 1, cipher_len, fin) != cipher_len) {
        fprintf(stderr, "❌ Đọc ciphertext thất bại\n");
        ret = 1; goto done;
    }

    printf("   🔒 Ciphertext: %zu bytes\n", cipher_len);
    printf("   📄 Kích thước gốc: %u bytes\n", hdr.orig_size);
    print_hex("   🔑 IV", hdr.iv, sizeof(hdr.iv));

    /* Giải mã qua driver */
    plaintext = driver_decrypt(ciphertext, cipher_len,
                               DEFAULT_KEY, hdr.iv, &plain_len);
    if (!plaintext) { ret = 1; goto done; }

    /* Cắt đúng kích thước gốc */
    if (plain_len > hdr.orig_size)
        plain_len = hdr.orig_size;

    /* Tạo tên file output (bỏ đuôi .enc) */
    strncpy(out_path, enc_path, sizeof(out_path) - 1);
    out_path[sizeof(out_path) - 1] = '\0';
    size_t plen = strlen(out_path);
    size_t ext_len = strlen(ENC_EXTENSION);
    if (plen > ext_len &&
        strcmp(out_path + plen - ext_len, ENC_EXTENSION) == 0)
        out_path[plen - ext_len] = '\0';
    else
        strncat(out_path, ".dec", sizeof(out_path) - strlen(out_path) - 1);

    fout = fopen(out_path, "wb");
    if (!fout) {
        fprintf(stderr, "❌ Không tạo được: %s\n", out_path);
        ret = 1; goto done;
    }

    fwrite(plaintext, 1, plain_len, fout);
    printf("   ✅ Đã giải mã: %s (%zu bytes)\n", out_path, plain_len);

done:
    if (fin)  fclose(fin);
    if (fout) fclose(fout);
    free(ciphertext);
    free(plaintext);
    return ret;
}

/* ===== Lệnh: list ===== */
static int cmd_list(const char *dir_path)
{
    DIR *d;
    struct dirent *ent;
    struct stat st;
    char full_path[512];
    int count = 0;
    const char *search_dir = dir_path ? dir_path : ".";

    d = opendir(search_dir);
    if (!d) {
        fprintf(stderr, "❌ Không mở được thư mục: %s\n", search_dir);
        return 1;
    }

    printf("📁 Danh sách file mã hóa trong: %s\n", search_dir);
    printf("%-40s %10s\n", "Tên file", "Kích thước");
    printf("%-40s %10s\n", "────────────────────────────────────────",
           "──────────");

    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        size_t ext_len = strlen(ENC_EXTENSION);
        if (nlen <= ext_len) continue;
        if (strcmp(ent->d_name + nlen - ext_len, ENC_EXTENSION) != 0) continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", search_dir, ent->d_name);
        if (stat(full_path, &st) == 0) {
            printf("%-40s %9lld B\n", ent->d_name, (long long)st.st_size);
            count++;
        }
    }

    closedir(d);

    if (count == 0)
        printf("(Không có file .enc nào)\n");
    else
        printf("\nTổng: %d file\n", count);

    return 0;
}

/* ===== Lệnh: view ===== */
static int cmd_view(const char *enc_path)
{
    uint8_t *ciphertext = NULL, *plaintext = NULL;
    struct enc_header hdr;
    size_t file_size, cipher_len, plain_len;
    FILE *fin = NULL;
    int ret = 0;

    fin = fopen(enc_path, "rb");
    if (!fin) {
        fprintf(stderr, "❌ Không mở được: %s\n", enc_path);
        return 1;
    }

    if (fread(&hdr, sizeof(hdr), 1, fin) != 1 ||
        memcmp(hdr.magic, ENC_MAGIC, ENC_MAGIC_LEN) != 0) {
        fprintf(stderr, "❌ Không phải file CAMF\n");
        ret = 1; goto done;
    }

    fseek(fin, 0, SEEK_END);
    file_size  = (size_t)ftell(fin);
    cipher_len = file_size - sizeof(hdr);

    fseek(fin, sizeof(hdr), SEEK_SET);
    ciphertext = malloc(cipher_len);
    if (!ciphertext || fread(ciphertext, 1, cipher_len, fin) != cipher_len) {
        ret = 1; goto done;
    }

    plaintext = driver_decrypt(ciphertext, cipher_len,
                               DEFAULT_KEY, hdr.iv, &plain_len);
    if (!plaintext) { ret = 1; goto done; }

    if (plain_len > hdr.orig_size) plain_len = hdr.orig_size;

    printf("📄 Nội dung: %s\n", enc_path);
    printf("────────────────────────────────────────\n");
    fwrite(plaintext, 1, plain_len, stdout);
    if (plain_len > 0 && plaintext[plain_len - 1] != '\n')
        printf("\n");
    printf("────────────────────────────────────────\n");
    printf("(%zu bytes)\n", plain_len);

done:
    if (fin) fclose(fin);
    free(ciphertext);
    free(plaintext);
    return ret;
}

/* ===== main ===== */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "encrypt") == 0) {
        if (argc < 3) { fprintf(stderr, "Thiếu tên file\n"); return 1; }
        return cmd_encrypt(argv[2]);
    }
    else if (strcmp(cmd, "decrypt") == 0) {
        if (argc < 3) { fprintf(stderr, "Thiếu tên file\n"); return 1; }
        return cmd_decrypt(argv[2]);
    }
    else if (strcmp(cmd, "list") == 0) {
        return cmd_list(argc >= 3 ? argv[2] : NULL);
    }
    else if (strcmp(cmd, "view") == 0) {
        if (argc < 3) { fprintf(stderr, "Thiếu tên file\n"); return 1; }
        return cmd_view(argv[2]);
    }
    else {
        fprintf(stderr, "❌ Lệnh không hợp lệ: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
