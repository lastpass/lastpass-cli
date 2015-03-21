/*
 * Copyright (c) 2014-2015 LastPass.
 */
#include "process.h"
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <limits.h>

#if defined(__linux__)
#include <sys/prctl.h>
#define USE_PRCTL
#elif defined(__APPLE__) && defined(__MACH__)
#include <libproc.h>
#include <sys/ptrace.h>
#define USE_PTRACE
#elif defined(__OpenBSD__)
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <kvm.h>
#endif

#ifndef USE_PRCTL
#undef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 0
#define PR_SET_NAME 0
static void prctl(__attribute__((unused)) int x,
		  __attribute__((unused)) int y) {}
#endif

#ifndef USE_PTRACE
#undef PT_DENY_ATTACH
#define PT_DENY_ATTACH 0
static void ptrace(__attribute__((unused)) int x,
		   __attribute__((unused)) int y,
		   __attribute__((unused)) int z,
		   __attribute__((unused)) int w) {}
#endif


#if defined(__linux__) || defined(__CYGWIN__) || defined(__NetBSD__)
#define DEVPROC_NAME "exe"
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#define DEVPROC_NAME "file"
#endif

#ifdef DEVPROC_NAME
static int pid_to_cmd(pid_t pid, char *cmd, size_t cmd_size)
{
	_cleanup_free_ char *proc;
	xasprintf(&proc, "/proc/%lu/" DEVPROC_NAME, (unsigned long)pid);
	return readlink(proc, cmd, cmd_size - 1);
}
#elif defined(__APPLE__) && defined(__MACH__)
static int pid_to_cmd(pid_t pid, char *cmd, size_t cmd_size)
{
	int result;
	result = proc_pidpath(pid, cmd, cmd_size);
	return (result <= 0) ? -1 : 0;
}
#elif defined(__OpenBSD__)
static int pid_to_cmd(pid_t pid, char *cmd, size_t cmd_size)
{
	int cnt, ret;
	kvm_t *kd;
	struct kinfo_proc *kp;

	ret = -1;

	if ((kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL)) == NULL)
		return ret;
	if ((kp = kvm_getprocs(kd, KERN_PROC_PID, (int)pid, sizeof(*kp), &cnt)) == NULL)
		goto out;
	if ((kp->p_flag & P_SYSTEM) != 0)
		goto out;
	if (cnt != 1)
		goto out;
	if (strlcpy(cmd, kp[0].p_comm, cmd_size) >= cmd_size)
		goto out;

	ret = 0;

out:
	kvm_close(kd);
	return ret;
}
#else
#error "Please provide a pid_to_cmd for your platform"
#endif

void process_set_name(const char *name)
{
	prctl(PR_SET_NAME, name);

	if (!ARGC || !ARGV)
		return;

	for (int i = 0; i < ARGC; ++i) {
		for (char *p = ARGV[i]; *p; ++p)
			*p = '\0';
	}

	strcpy(ARGV[0], name);
}

bool process_is_same_executable(pid_t pid)
{
	char resolved_them[PATH_MAX + 1] = { 0 }, resolved_me[PATH_MAX + 1] = { 0 };

	if (pid_to_cmd(pid, resolved_them, sizeof(resolved_them)) < 0 ||
	    pid_to_cmd(getpid(), resolved_me, sizeof(resolved_me)) < 0)
		return false;

	return strcmp(resolved_them, resolved_me) == 0;
}

void process_disable_ptrace(void)
{
	prctl(PR_SET_DUMPABLE, 0);
	ptrace(PT_DENY_ATTACH, 0, 0, 0);

	struct rlimit limit = { 0, 0 };
	setrlimit(RLIMIT_CORE, &limit);
}
