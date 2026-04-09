#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0xf46d5bf3, "mutex_unlock" },
	{ 0x37c0b5f3, "__request_module" },
	{ 0x37031a65, "__register_chrdev" },
	{ 0x653aa194, "class_create" },
	{ 0xe486c4b7, "device_create" },
	{ 0x52b15b3b, "__unregister_chrdev" },
	{ 0xa1dacb42, "class_destroy" },
	{ 0x1595e410, "device_destroy" },
	{ 0xa1dacb42, "class_unregister" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xa53f4e29, "memcpy" },
	{ 0x92a517f6, "crypto_alloc_skcipher" },
	{ 0xa9f25797, "crypto_skcipher_setkey" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x66526f72, "sg_init_one" },
	{ 0x236a2cc3, "crypto_skcipher_encrypt" },
	{ 0x026921de, "crypto_destroy_tfm" },
	{ 0x236a2cc3, "crypto_skcipher_decrypt" },
	{ 0xf8faa012, "kfree_sensitive" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xfaabfe5e, "kmalloc_caches" },
	{ 0xc064623f, "__kmalloc_cache_noprof" },
	{ 0x23ef80fb, "default_llseek" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xf1de9e85, "kvfree" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0xe8213e80, "_printk" },
	{ 0xf46d5bf3, "mutex_lock" },
	{ 0xf52f8b44, "__kvmalloc_node_noprof" },
	{ 0x546c19d9, "validate_usercopy_range" },
	{ 0xbebe66ff, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xa61fd7aa,
	0x092a35a2,
	0xf46d5bf3,
	0x37c0b5f3,
	0x37031a65,
	0x653aa194,
	0xe486c4b7,
	0x52b15b3b,
	0xa1dacb42,
	0x1595e410,
	0xa1dacb42,
	0xbd03ed67,
	0x092a35a2,
	0xe54e0a6b,
	0xa53f4e29,
	0x92a517f6,
	0xa9f25797,
	0xd710adbf,
	0x66526f72,
	0x236a2cc3,
	0x026921de,
	0x236a2cc3,
	0xf8faa012,
	0xd272d446,
	0xbd03ed67,
	0xfaabfe5e,
	0xc064623f,
	0x23ef80fb,
	0xd272d446,
	0xd272d446,
	0xf1de9e85,
	0xcb8b6ec6,
	0xe8213e80,
	0xf46d5bf3,
	0xf52f8b44,
	0x546c19d9,
	0xbebe66ff,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__check_object_size\0"
	"_copy_from_user\0"
	"mutex_unlock\0"
	"__request_module\0"
	"__register_chrdev\0"
	"class_create\0"
	"device_create\0"
	"__unregister_chrdev\0"
	"class_destroy\0"
	"device_destroy\0"
	"class_unregister\0"
	"__ref_stack_chk_guard\0"
	"_copy_to_user\0"
	"__fortify_panic\0"
	"memcpy\0"
	"crypto_alloc_skcipher\0"
	"crypto_skcipher_setkey\0"
	"__kmalloc_noprof\0"
	"sg_init_one\0"
	"crypto_skcipher_encrypt\0"
	"crypto_destroy_tfm\0"
	"crypto_skcipher_decrypt\0"
	"kfree_sensitive\0"
	"__stack_chk_fail\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"default_llseek\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"kvfree\0"
	"kfree\0"
	"_printk\0"
	"mutex_lock\0"
	"__kvmalloc_node_noprof\0"
	"validate_usercopy_range\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "7C27326DFCC68EA053F5D13");
