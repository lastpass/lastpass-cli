/*
 * queue for changes uploaded to LastPass
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
#include "password.h"
#include "util.h"
#include "terminal.h"
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <errno.h>
#include <termios.h>

static char *password_prompt_askpass(const char *askpass, const char *prompt, const char *error, const char *descfmt, va_list params)
{
	int status;
	int write_fds[2], read_fds[2];
	pid_t child;
	FILE *output;
	char *password = NULL, *lastlf;
	size_t len;
	UNUSED(error);
	UNUSED(descfmt);
	UNUSED(params);

	if (pipe(write_fds) < 0 || pipe(read_fds) < 0)
		die_errno("pipe");

	child = fork();
	if (child == -1)
		die_errno("fork");

	if (child == 0) {
		dup2(read_fds[1], STDOUT_FILENO);

		close(read_fds[0]);
		close(read_fds[1]);
		close(write_fds[0]);
		close(write_fds[1]);
		execlp(askpass, "lpass-askpass", prompt, NULL);
		_exit(76);
	}
	close(read_fds[1]);
	close(write_fds[0]);
	close(write_fds[1]);

	output = fdopen(read_fds[0], "r");
	if (!output)
		die_errno("fdopen");

	if (getline(&password, &len, output) < 0) {
		free(password);
		die("Unable to retrieve password from askpass (no reply)");
	}
	lastlf = strrchr(password, '\n');
	if (lastlf)
		*lastlf = '\0';
	waitpid(child, &status, 0);

	if (WEXITSTATUS(status) == 76) {
		die("Unable to execute askpass %s", askpass);
	} else if (WEXITSTATUS(status)) {
		die("There was an unspecified problem with askpass (%d)",
		    WEXITSTATUS(status));
	}
	return password;
}

static char *password_prompt_fallback(const char *prompt, const char *error, const char *descfmt, va_list params)
{
	struct termios old_termios, mask_echo;
	char *password = NULL, *lastlf;
	size_t len = 0;

	terminal_fprintf(stderr, TERMINAL_FG_YELLOW TERMINAL_BOLD);
	vfprintf(stderr, descfmt, params);
	terminal_fprintf(stderr, TERMINAL_RESET "\n\n");

	if (error)
		terminal_fprintf(stderr, TERMINAL_FG_RED TERMINAL_BOLD "%s" TERMINAL_RESET "\n", error);

	terminal_fprintf(stderr, TERMINAL_BOLD "%s" TERMINAL_RESET ": ", prompt);

	if (isatty(STDIN_FILENO)) {
		if (tcgetattr(STDIN_FILENO, &old_termios) < 0)
			die_errno("tcgetattr");
		mask_echo = old_termios;
		mask_echo.c_lflag &= ~(ICANON | ECHO);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &mask_echo) < 0)
			die_errno("tcsetattr");
	}

	if (getline(&password, &len, stdin) < 0) {
		free(password);
		password = NULL;
		goto out;
	}
	fprintf(stderr, "\n");
	lastlf = strrchr(password, '\n');
	if (lastlf)
		*lastlf = '\0';

out:
	if (isatty(STDIN_FILENO)) {
		if (tcsetattr(STDIN_FILENO, TCSANOW, &old_termios) < 0)
			die_errno("tcsetattr");
	}

	terminal_fprintf(stderr, "%s" TERMINAL_CLEAR_DOWN, error ? TERMINAL_UP_CURSOR(4) : TERMINAL_UP_CURSOR(3));
	return password;
}

char *pinentry_escape(const char *str)
{
	int len, new_len;
	char *escaped;

	if (!str)
		return NULL;

	new_len = len = strlen(str);

	for (int i = 0; i < len; ++i) {
		if (str[i] == '%' || str[i] == '\r' || str[i] == '\n')
			new_len += 2;
	}

	escaped = xcalloc(new_len + 1, 1);

	for (int i = 0, j = 0; i < len; ++i, ++j) {
		if (str[i] == '%') {
			escaped[j] = '%';
			escaped[j + 1] = '2';
			escaped[j + 2] = '5';
			j += 2;
		} else if (str[i] == '\r') {
			escaped[j] = '%';
			escaped[j + 1] = '0';
			escaped[j + 2] = 'd';
			j += 2;
		} else if (str[i] == '\n') {
			escaped[j] = '%';
			escaped[j + 1] = '0';
			escaped[j + 2] = 'a';
			j += 2;
		} else
			escaped[j] = str[i];
	}

	return escaped;
}

char *pinentry_unescape(const char *str)
{
	char *unescaped;
	char hex[3];
	int len;

	if (!str)
		return NULL;

	len = strlen(str);
	unescaped = xcalloc(len + 1, 1);

	for (int i = 0, j = 0; i < len; ++i, ++j) {
		if (str[i] == '%') {
			if (i + 2 >= len)
				break;
			hex[0] = str[i + 1];
			hex[1] = str[i + 2];
			hex[2] = '\0';
			i += 2;
			unescaped[j] = strtoul(hex, NULL, 16);
		} else
			unescaped[j] = str[i];
	}

	return unescaped;
}

char *password_prompt(const char *prompt, const char *error, const char *descfmt, ...)
{
	int status;
	int write_fds[2], read_fds[2];
	pid_t child;
	size_t len = 0, total_len, new_len;
	_cleanup_fclose_ FILE *input = NULL;
	_cleanup_fclose_ FILE *output = NULL;
	_cleanup_free_ char *line = NULL;
	_cleanup_free_ char *desc = NULL;
	_cleanup_free_ char *prompt_colon = NULL;
	_cleanup_free_ char *password = NULL;
	char *password_fallback;
	char *askpass;
	char *ret;
	va_list params;
	int devnull;

	askpass = getenv("LPASS_ASKPASS");
	if (askpass) {
		va_start(params, descfmt);
		askpass = password_prompt_askpass(askpass, prompt, error, descfmt, params);
		va_end(params);
		return askpass;
	}

	password_fallback = getenv("LPASS_DISABLE_PINENTRY");
	if (password_fallback && !strcmp(password_fallback, "1")) {
		va_start(params, descfmt);
		password_fallback = password_prompt_fallback(prompt, error, descfmt, params);
		va_end(params);
		return password_fallback;
	}

	if (pipe(write_fds) < 0 || pipe(read_fds) < 0)
		die_errno("pipe");

	child = fork();
	if (child == -1)
		die_errno("fork");

	if (child == 0) {
		dup2(read_fds[1], STDOUT_FILENO);
		dup2(write_fds[0], STDIN_FILENO);

		devnull = open("/dev/null", O_WRONLY);
		dup2(devnull, STDERR_FILENO);

		close(read_fds[0]);
		close(read_fds[1]);
		close(write_fds[0]);
		close(write_fds[1]);
		execlp("pinentry", "pinentry", NULL);
		_exit(76);
	}
	close(read_fds[1]);
	close(write_fds[0]);

	input = fdopen(write_fds[1], "w");
	output = fdopen(read_fds[0], "r");
	if (!input || !output)
		die_errno("fdopen");


	#define nextline() do { \
		if (len) \
			secure_clear(line, len); \
		len = 0; \
		free(line); \
		line = NULL; \
		if (getline(&line, &len, output) < 0) \
			goto dead_pinentry; \
		len = strlen(line); \
	} while (0)

	#define check() do { \
		nextline(); \
		if (!starts_with(line, "OK")) \
			goto dead_pinentry; \
	} while (0)

	#define send(command, argument) do { \
		if (argument == NULL) \
			fprintf(input, command "\n"); \
		else { \
			_cleanup_free_ char *cleaned = pinentry_escape(argument); \
			fprintf(input, command " %s\n", cleaned); \
		} \
		fflush(input); \
	} while (0)

	#define option(name, val) do { \
		char *var = val, *option, *key = name; \
		if (var) { \
			var = pinentry_escape(var); \
			xasprintf(&option, "%s=%s", key, var); \
			send("OPTION", option); \
			free(var); \
			free(option); \
			check(); \
		} \
	} while(0)

	check();

	send("SETTITLE", "LastPass CLI");
	check();

	if (prompt) {
		xasprintf(&prompt_colon, "%s:", prompt);
		prompt = prompt_colon;
	}
	send("SETPROMPT", prompt);
	check();

	if (error) {
		send("SETERROR", error);
		check();
	}

	va_start(params, descfmt);
	xvasprintf(&desc, descfmt, params);
	va_end(params);

	send("SETDESC", desc);
	check();

	option("ttytype", getenv("TERM"));
	option("ttyname", ttyname(0));
	option("display", getenv("DISPLAY"));

	send("GETPIN", NULL);
	total_len = 1;
	password = xcalloc(total_len, 1);
	for (;;) {
		nextline();
		if (starts_with(line, "D")) {
			if (len >= 3) {
				new_len = total_len + len - 3;
				password = secure_resize(password, total_len, new_len);
				total_len = new_len;
				strlcat(password, line + 2, total_len);
			}
		} else if (starts_with(line, "OK"))
			break;
		else {
			free(password);
			password = NULL;
			break;
		}
	}

	send("BYE", NULL);

	#undef nextline
	#undef check
	#undef send
	#undef option

	waitpid(child, NULL, 0);

	if (len)
		secure_clear(line, len);

	ret = pinentry_unescape(password);
	secure_clear_str(password);
	return ret;

dead_pinentry:
	if (waitpid(child, &status, WNOHANG) <= 0) {
		sleep(1);
		if (waitpid(child, &status, WNOHANG) <= 0) {
			kill(child, SIGTERM);
			sleep(1);
			if (waitpid(child, &status, WNOHANG) <= 0) {
				kill(child, SIGKILL);
				waitpid(child, &status, 0);
			}
		}
	}
	if (WEXITSTATUS(status) == 0)
		return NULL;
	else if (WEXITSTATUS(status) == 76) {
		va_start(params, descfmt);
		password_fallback = password_prompt_fallback(prompt, error, descfmt, params);
		va_end(params);
		return password_fallback;
	} else
		die("There was an unspecified problem with pinentry.");
}
