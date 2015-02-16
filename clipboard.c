/*
 * Copyright (c) 2014 LastPass.
 *
 *
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
		execlp("xclip", "xclip", "-selection", "clipboard", "-in", NULL);
		execlp("xsel", "xsel", "--clipboard", "--input", NULL);
		execlp("pbcopy", "pbcopy", NULL);
		execlp("putclip", "putclip", "--dos", NULL);
		die("Unable to copy contents to clipboard. Please make sure you have `xclip`, `xsel`, `pbcopy`, or `putclip` installed.");
	}
	close(pipefd[0]);
	dup2(pipefd[1], STDOUT_FILENO);
	close(pipefd[1]);

	if (!registered_closer) {
		atexit(clipboard_close);
		registered_closer = true;
	}
}
