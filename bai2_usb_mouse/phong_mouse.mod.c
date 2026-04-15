#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
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

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xfd83e3e2, "input_unregister_device" },
	{ 0x931f4cb0, "usb_free_urb" },
	{ 0xc5eee22c, "usb_free_coherent" },
	{ 0x37a0cba, "kfree" },
	{ 0x122c3a7e, "_printk" },
	{ 0xec743506, "input_event" },
	{ 0x814e7be6, "usb_submit_urb" },
	{ 0xceb19f3e, "_dev_err" },
	{ 0x3cf0639e, "usb_deregister" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0x1004e946, "kmalloc_caches" },
	{ 0xbf55f104, "kmalloc_trace" },
	{ 0x77b9ade7, "input_allocate_device" },
	{ 0xf0f3a49e, "usb_alloc_coherent" },
	{ 0x57f427e2, "usb_alloc_urb" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xa916b694, "strnlen" },
	{ 0x79b69418, "input_register_device" },
	{ 0xcd080695, "input_free_device" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x805f3047, "usb_register_driver" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xa78ce5b7, "usb_kill_urb" },
	{ 0x73776b79, "module_layout" },
};

MODULE_INFO(depends, "");

MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic03isc01ip02in*");

MODULE_INFO(srcversion, "77BD74900D6D05996CEE825");
