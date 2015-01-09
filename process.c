/*
 * Copyright (c) 2014 LastPass.
 *
 * 
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
#elif defined(__APPLE__) && defined(__MACH__)
#include <libproc.h>
#include <sys/ptrace.h>
#elif defined(__OpenBSD__)
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <kvm.h>
#endif

void process_set_name(const char *name)
{
#if defined(__linux__)
	prctl(PR_SET_NAME, name);
#endif

	if (!ARGC || !ARGV)
		return;

	for (int i = 0; i < ARGC; ++i) {
		for (char *p = ARGV[i]; *p; ++p)
			*p = '\0';
	}

	strcpy(ARGV[0], name);
}

#if defined(__linux__) || defined(__CYGWIN__)
#define DEVPROC_NAME "exe"
#define DEVPROC_SELF "self"
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#define DEVPROC_NAME "file"
#define DEVPROC_SELF "curproc"
#elif defined(__NetBSD__)
#define DEVPROC_NAME "exe"
#define DEVPROC_SELF "curproc"
#endif

#if defined(DEVPROC_NAME)
bool process_is_same_executable(pid_t pid)
{
	_cleanup_free_ char *proc = NULL;
	char resolved_them[PATH_MAX + 1] = { 0 }, resolved_me[PATH_MAX + 1] = { 0 };

	xasprintf(&proc, "/proc/%lu/" DEVPROC_NAME, (unsigned long)pid);
	if (readlink(proc, resolved_them, PATH_MAX) < 0 || readlink("/proc/" DEVPROC_SELF "/" DEVPROC_NAME, resolved_me, PATH_MAX) < 0)
		return false;
	if (strcmp(resolved_them, resolved_me))
		return false;
	return true;

}

void process_disable_ptrace(void)
{
#if defined(__linux__)
	prctl(PR_SET_DUMPABLE, 0);
#endif
	struct rlimit limit = { 0, 0 };
	setrlimit(RLIMIT_CORE, &limit);
}
#elif defined(__APPLE__) && defined(__MACH__)
bool process_is_same_executable(pid_t pid)
{
	char resolved_them[PROC_PIDPATHINFO_MAXSIZE], resolved_me[PROC_PIDPATHINFO_MAXSIZE];

	if (proc_pidpath(pid, resolved_them, sizeof(resolved_them)) <= 0 || proc_pidpath(getpid(), resolved_me, sizeof(resolved_me)) <= 0)
		return false;
	if (strcmp(resolved_them, resolved_me))
		return false;
	return true;
}

void process_disable_ptrace(void)
{
	ptrace(PT_DENY_ATTACH, 0, 0, 0);
	struct rlimit limit = { 0, 0 };
	setrlimit(RLIMIT_CORE, &limit);
}
#elif defined(__OpenBSD__)
int pid_to_cmd(pid_t pid, char *cmd)
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
	if (strlcpy(cmd, kp[0].p_comm, sizeof(cmd)) >= sizeof(cmd))
		goto out;

	ret = 0;

out:
	kvm_close(kd);
	return ret;
}

bool process_is_same_executable(pid_t pid)
{
	char resolved_them[PATH_MAX], resolved_me[PATH_MAX];

	if (pid_to_cmd(pid, resolved_them) || pid_to_cmd(getpid(), resolved_me))
		return false;
	if (strcmp(resolved_them, resolved_me))
		return false;
	return true;
}

void process_disable_ptrace(void)
{
	struct rlimit limit = { 0, 0 };
	setrlimit(RLIMIT_CORE, &limit);
}
#endif
