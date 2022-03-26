#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Adrian Brodzik, Piotr Frątczak");
MODULE_DESCRIPTION("Anti-reconnaissance kernel module.");

int init_module()
{
    pr_info("init\n");
    return 0;
}

void cleanup_module()
{
    pr_info("exit\n");
}
