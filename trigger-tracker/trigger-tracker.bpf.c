#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AD_PROG_FILENAME "python"
#define AD_PROG_ARG1 "BLABLA.py"
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1024);
    __type(value, bool);
} map_ads SEC(".maps");

struct _trace_event_raw_sys_enter
{
    struct trace_entry ent;
    long int id;
    const char *args[6];
    char __data[0];
};

struct enter_execve_ctx
{
    long long data;
    const char *filename;
    const char *argv;
    const char *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct _trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;

    // Making sure there's no infinite loop
    // Need to get the execve'd program name
    const char *filename = ctx->args[0];
    if (bpf_strncmp(AD_PROG_FILENAME, sizeof(AD_PROG_FILENAME), filename) == 0)
    {
        return 0;
    }
    char **argv = (char **)ctx->args[1];
    if (bpf_strncmp(argv[0], sizeof(AD_PROG_ARG1), AD_PROG_ARG1) == 0)
    {
        return 0;
    }

    // We know its not an ad, so we can load one
    int dummy = 0;
    if (bpf_map_push_elem(&map_ads, &dummy, 0) < 0)
    {
        bpf_printk("Failed to push ad to ad queue map.");
        return 0;
    }
    return 0;
}