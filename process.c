/*
 * lpass process settings
 *
 * Copyright (C) 2014-2015 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
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
	size_t argslen = 0;
	prctl(PR_SET_NAME, name);

	if (!ARGC || !ARGV)
		return;

	for (int i = 0; i < ARGC; ++i) {
		argslen += strlen(ARGV[i]) + 1;
		for (char *p = ARGV[i]; *p; ++p)
			*p = '\0';
	}

	strlcpy(ARGV[0], name, argslen);
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
