/*
 * agent for caching decryption key
 *
 * Copyright (C) 2014-2018 LastPass.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include "agent.h"
#include "config.h"
#include "util.h"
#include "password.h"
#include "terminal.h"
#include "process.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#if (defined(__unix__) || defined(unix)) && !defined(USG)
#include <sys/param.h>
#endif

#if !defined(SUN_LEN)
#define SUN_LEN(su) \
        (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#if !defined(__linux__) && !defined(__CYGWIN__)
#define SOCKET_SEND_PID 1
struct ucred {
	pid_t pid;
	uid_t uid;
	gid_t gid;
};
#endif

#define AGENT_VERIFICATION_STRING "`lpass` was written by LastPass.\n"

static inline char *agent_socket_path(void)
{
	return config_path("agent.sock");
}

bool agent_load_key(unsigned char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *iterationbuf = NULL;
	_cleanup_free_ char *verify = NULL;
	_cleanup_free_ char *username = NULL;
	_cleanup_free_ char *password = NULL;
	int iterations;

	iterationbuf = config_read_string("iterations");
	username = config_read_string("username");
	if (!iterationbuf || !username || !config_exists("verify"))
		return false;
	iterations = strtoul(iterationbuf, NULL, 10);
	if (iterations <= 0)
		return false;

	for (;;) {
		free(password);
		password = password_prompt("Master Password", password ? "Incorrect master password; please try again." : NULL, "Please enter the LastPass master password for <%s>.", username);
		if (!password)
			return false;
		kdf_decryption_key(username, password, iterations, key);

		/* no longer need password contents, zero it */
		secure_clear_str(password);

		verify = config_read_encrypted_string("verify", key);
		if (verify && !strcmp(verify, AGENT_VERIFICATION_STRING))
			break;
	}

	return true;
}

_noreturn_ static void agent_cleanup(int signal)
{
	UNUSED(signal);
	char *path = agent_socket_path();
	unlink(path);
	free(path);
	_exit(EXIT_SUCCESS);
}

#if defined(__linux__) || defined(__CYGWIN__)
static int agent_socket_get_cred(int fd, struct ucred *cred)
{
	socklen_t credlen = sizeof(struct ucred);
	return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, cred, &credlen);
}
#elif defined(__APPLE__) && defined(__MACH__) || defined(BSD)
static int agent_socket_get_cred(int fd, struct ucred *cred)
{
	if (getpeereid(fd, &cred->uid, &cred->gid) < 0)
		return -1;

	if (read(fd, &cred->pid, sizeof(cred->pid)) != sizeof(cred->pid))
		return -1;

	return 0;
}
#endif

void _assert_socket_sun_path(struct sockaddr_un *sa, char *path)
{
	if (strlen(path) >= sizeof(sa->sun_path)) {
		die("Path too large for agent control socket.");
	}
}

int _setup_agent_socket(struct sockaddr_un *sa, char *path)
{
	int fd;

	_assert_socket_sun_path(sa, path);
	memset(sa, 0, sizeof(*sa));
	sa->sun_family = AF_UNIX;
	strlcpy(sa->sun_path, path, sizeof(sa->sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	return fd;
}

static void agent_run(unsigned const char key[KDF_HASH_LEN], int status_event_fd)
{
	char *agent_timeout_str;
	unsigned int agent_timeout;
	struct sockaddr_un sa, listensa;
	struct ucred cred;
	int fd, listenfd;
	socklen_t len;
	char status_event[64];

	signal(SIGHUP, agent_cleanup);
	signal(SIGINT, agent_cleanup);
	signal(SIGQUIT, agent_cleanup);
	signal(SIGTERM, agent_cleanup);
	signal(SIGALRM, agent_cleanup);

	agent_timeout_str = getenv("LPASS_AGENT_TIMEOUT");
	agent_timeout = 60 * 60; /* One hour by default. */
	if (agent_timeout_str && strlen(agent_timeout_str))
		agent_timeout = strtoul(agent_timeout_str, NULL, 10);
	if (agent_timeout)
		alarm(agent_timeout);

	_cleanup_free_ char *path = agent_socket_path();
	fd = _setup_agent_socket(&sa, path);

	unlink(path);

	if (bind(fd, (struct sockaddr *)&sa, SUN_LEN(&sa)) < 0 || listen(fd, 16) < 0) {
		listenfd = errno;
		close(fd);
		unlink(path);
		errno = listenfd;

		strcpy(status_event, "FAILED"); // send that we failed to successfully spawn to the process
		if (write(status_event_fd, status_event, 64) < 0) {
			fprintf(stderr, "Failed to send the error status to parent process.\n");
		}

		die_errno("bind|listen");
	}

	strcpy(status_event, "READY"); // notify to the calling process that we're in a ready state - they're free to exit.
	if (write(status_event_fd, status_event, 64) < 0) {
		fprintf(stderr, "Failed to notify the parent process that we are listening. Continuing anyways.\n");
	}

	close(status_event_fd);

	for (len = sizeof(listensa); (listenfd = accept(fd, (struct sockaddr *)&listensa, &len)) > 0; len = sizeof(listensa)) {
		if (agent_socket_get_cred(listenfd, &cred) < 0) {
			close(listenfd);
			continue;
		}
		if (cred.uid != getuid() || cred.gid != getgid() || !process_is_same_executable(cred.pid)) {
			close(listenfd);
			continue;
		}

#if SOCKET_SEND_PID == 1
		pid_t pid = getpid();
		IGNORE_RESULT(write(listenfd, &pid, sizeof(pid)));
#endif
		IGNORE_RESULT(write(listenfd, key, KDF_HASH_LEN));
		close(listenfd);
	}

	listenfd = errno;
	close(fd);
	unlink(path);
	errno = listenfd;
	die_errno("accept");
}

void agent_kill(void)
{
	struct sockaddr_un sa;
	struct ucred cred;
	int fd;

	_cleanup_free_ char *path = agent_socket_path();
	fd = _setup_agent_socket(&sa, path);

	if (connect(fd, (struct sockaddr *)&sa, SUN_LEN(&sa)) < 0)
		goto out;

#if SOCKET_SEND_PID == 1
	pid_t pid = getpid();
	if (write(fd, &pid, sizeof(pid)) != sizeof(pid))
		goto out;
#endif

	if (agent_socket_get_cred(fd, &cred) < 0)
		goto out;

	kill(cred.pid, SIGTERM);

out:
	close(fd);
}

bool agent_ask(unsigned char key[KDF_HASH_LEN])
{
	struct sockaddr_un sa;
	int fd;
	bool ret = false;

	_cleanup_free_ char *path = agent_socket_path();
	fd = _setup_agent_socket(&sa, path);

	ret = connect(fd, (struct sockaddr *)&sa, SUN_LEN(&sa)) >= 0;
	if (!ret)
		goto out;

#if SOCKET_SEND_PID == 1
	pid_t pid = getpid();
	ret = write(fd, &pid, sizeof(pid)) == sizeof(pid);
	if (!ret)
		goto out;
	ret = read(fd, &pid, sizeof(pid)) == sizeof(pid);
	if (!ret)
		goto out;
#endif
	ret = read(fd, key, KDF_HASH_LEN) == KDF_HASH_LEN;
	if (!ret)
		goto out;

out:
	close(fd);
	return ret;
}

static void agent_start(unsigned const char key[KDF_HASH_LEN])
{
	pid_t child;

	agent_kill();

	if (config_exists("plaintext_key"))
		return;

	char *disable_str = getenv("LPASS_AGENT_DISABLE");
	if (disable_str && !strcmp(disable_str, "1")) {
		return;
	}

	int agent_status_pipe[2];
	if(pipe(agent_status_pipe) < 0) {
		die("Failed to make pipe for agent process.");
	}

	child = fork();
	if (child < 0)
		die_errno("fork(agent)");

	if (child == 0) {
		int null = open("/dev/null", 0);
		if (null < 0)
			_exit(EXIT_FAILURE);
		dup2(null, 0);
		dup2(null, 1);
		dup2(null, 2);
		close(null);
		setsid();
		if (chdir("/") < 0)
			_exit(EXIT_FAILURE);
		process_disable_ptrace();
		process_set_name("lpass [agent]");

		close(agent_status_pipe[0]);
		agent_run(key, agent_status_pipe[1]);
		_exit(EXIT_FAILURE);
	}

	if (child > 0) {
		close(agent_status_pipe[1]);

		char status[64];
		if (read(agent_status_pipe[0], status, 64) < 0) { // wait for agent to spawn successfully before exiting.
			die("Failed to read bringup status from agent");
		}

		if(strcmp(status, "FAILED") == 0) {
			die("Failed to bringup agent.");
		}
		return;
		close(agent_status_pipe[0]);
	}
}

bool agent_get_decryption_key(unsigned char key[KDF_HASH_LEN])
{
	if (config_exists("plaintext_key")) {
		_cleanup_free_ unsigned char *key_buffer = NULL;
		if (config_read_buffer("plaintext_key", &key_buffer) == KDF_HASH_LEN) {
			_cleanup_free_ char *verify = config_read_encrypted_string("verify", (unsigned char *)key_buffer);
			if (!verify || strcmp(verify, AGENT_VERIFICATION_STRING))
				goto badkey;
			memcpy(key, key_buffer, KDF_HASH_LEN);
			secure_clear(key_buffer, KDF_HASH_LEN);
			mlock(key, KDF_HASH_LEN);
			return true;
		}
		badkey: config_unlink("plaintext_key");
	}
	if (!agent_ask(key)) {
		if (!agent_load_key(key))
			return false;
		agent_start(key);
	}
	mlock(key, KDF_HASH_LEN);
	return true;
}

void agent_save(const char *username, int iterations, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *iterations_str = xultostr(iterations);
	config_write_string("iterations", iterations_str);
	config_write_string("username", username);
	config_write_encrypted_string("verify", AGENT_VERIFICATION_STRING, key);
	agent_start(key);
}
