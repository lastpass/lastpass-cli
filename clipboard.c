/*
 * system copy/paste routines
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

#include "clipboard.h"
#include "util.h"
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

static pid_t clipboard_process = 0;
static int saved_stdout = -1; 
static bool registered_closer = false;

void clipboard_close(void)
{
	if (!clipboard_process || saved_stdout < 0)
		return;

	fflush(stdout);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);
	waitpid(clipboard_process, NULL, 0);
	clipboard_process = 0;
	saved_stdout = -1;
}

void exec_command(char *command) {
	char *shell = getenv("SHELL");

	if (!shell) {
		shell = "/bin/sh";
	}

	execlp(shell, shell, "-c", command, NULL);
}

void clipboard_open(void)
{
	int pipefd[2];

	if (clipboard_process > 0)
		return;

	if (pipe(pipefd) < 0)
		die_errno("pipe");
	saved_stdout = dup(STDOUT_FILENO);
	if (saved_stdout < 0)
		die_errno("dup");
	clipboard_process = fork();
	if (clipboard_process == -1)
		die_errno("fork");
	if (!clipboard_process) {
		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);
		char *clipboard_command = getenv("LPASS_CLIPBOARD_COMMAND");
		if (clipboard_command) {
			exec_command(clipboard_command);
			die("Unable to copy contents to clipboard. Please make sure you have `xclip`, `xsel`, `pbcopy`, or `putclip` installed.");
		} else {
			execlp("xclip", "xclip", "-selection", "clipboard", "-in", NULL);
			execlp("xsel", "xsel", "--clipboard", "--input", NULL);
			execlp("pbcopy", "pbcopy", NULL);
			execlp("putclip", "putclip", "--dos", NULL);
			die("Unable to copy contents to clipboard. Please make sure you have `xclip`, `xsel`, `pbcopy`, or `putclip` installed.");
		}
	}
	close(pipefd[0]);
	dup2(pipefd[1], STDOUT_FILENO);
	close(pipefd[1]);

	if (!registered_closer) {
		atexit(clipboard_close);
		registered_closer = true;
	}
}
