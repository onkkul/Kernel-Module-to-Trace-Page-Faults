#include<linux/cdev.h>
#include<linux/device.h>
#include<linux/errno.h>
#include<linux/init.h>
#include<linux/fs.h>
#include<linux/kernel.h>
#include<linux/kprobes.h>
#include<linux/list.h>
#include<linux/math64.h>
#include<linux/module.h>
#include<linux/moduleparam.h>
#include<linux/miscdevice.h>
#include<linux/sched.h>
#include<linux/sched/signal.h>
#include<linux/semaphore.h>
#include<linux/slab.h>
#include<linux/types.h>
#include<linux/uaccess.h>

#define MAX_SYMBOL_LEN  64
#define plotSize 500
static char symbol[MAX_SYMBOL_LEN] = "handle_mm_fault";

static char tpid[MAX_SYMBOL_LEN] = "00000";

module_param_string(tpid, tpid, sizeof(tpid), 0644);

static struct kprobe kp =
{
    .symbol_name    = symbol,
};

struct vm_area_struct *vma_struct;
struct mm_struct *memory_manager;
struct task_struct *task_structure;


int counter = 0;
long addresses[plotSize];
long long timestamp[plotSize];

char plot[30][71];

s64 time_min, time_max, time_delta, time_bin;
s64 page_min, page_max, page_delta, page_bin;

/* kprobe pre_handler: called just before the probed instruction is executed */
// vm_fault_t handle_mm_fault(di_family_regirster, si_family_regirster, dx_family_register)
// vm_fault_t handle_mm_fault(struct vm_area_struct *vma_struct, unsigned long address, unsigned int flags)
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int process_ID = 0;
    char instructionAddress[12];
    char baseAddress[12];
    char zero[1] ={"0"};
    long tempAddressHolder;
    int i;
    #ifdef CONFIG_X86
        vma_struct=(struct vm_area_struct *)regs->di;

        memory_manager = (struct mm_struct *)vma_struct->vm_mm;

        task_structure = (struct task_struct *)memory_manager->owner;

        sscanf(tpid, "%d", &process_ID);

        if (task_structure->pid == process_ID && process_ID != 00000)
        {

            sprintf(instructionAddress, "%lx", regs->si);

            for(i=0;i<12;i++)
            {
                if(i<9) { baseAddress[i] = instructionAddress[i];}
                else    {baseAddress[i] = zero[0];}
            }

            pr_info("<%s> PID = %d Address: %s Time = %lld\n",
            p->symbol_name, task_structure->pid, baseAddress, ktime_to_us(ktime_get()));
            sscanf(baseAddress, "%ld", &tempAddressHolder);
        }
    #endif
    return 0;
}


/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p,
    struct pt_regs *regs, unsigned long flags)
{
}


static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);

    return 0;    // Return 0 because we don't handle the fault.
}

static int __init kprobe_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;


    ret = register_kprobe(&kp);
    if (ret < 0)
    {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %p\n", kp.addr);


    return 0;

}


static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}


module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
