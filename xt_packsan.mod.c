#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x6fe1db55, "module_layout" },
	{ 0x113a113e, "xt_unregister_match" },
	{ 0x2a730576, "xt_register_match" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x25ec1b28, "strlen" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0x4c4fef19, "kernel_stack" },
	{ 0x37a0cba, "kfree" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x4aabc7c4, "__tracepoint_kmalloc" },
	{ 0x6e787f7c, "slab_buffer_size" },
	{ 0xb3dd40, "kmem_cache_alloc_notrace" },
	{ 0xac971704, "malloc_sizes" },
	{ 0xea147363, "printk" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=x_tables";


MODULE_INFO(srcversion, "7D2404C42FFB5610DAA3DD9");
