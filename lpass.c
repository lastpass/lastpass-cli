/*
 * lpass - lastpass command line utility
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
#include "cmd.h"
#include "string.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "version.h"
#include <sys/stat.h>
#include <getopt.h>

#define CMD(name) { #name, cmd_##name##_usage, cmd_##name }
static struct {
	const char *name;
	const char *usage;
	int (*cmd)(int, char**);
} commands[] = {
	CMD(login),
	CMD(logout),
	CMD(show),
	CMD(ls),
	CMD(edit),
	CMD(generate),
	CMD(duplicate),
	CMD(rm),
	CMD(sync),
	CMD(export),
	CMD(share)
};
#undef CMD

static void version(void)
{
	terminal_printf("LastPass CLI v" LASTPASS_CLI_VERSION "\n");
}

static void help(void)
{
	terminal_printf("Usage:\n");
	printf("  %s {--help|--version}\n", ARGV[0]);
	for (size_t i = 0; i < ARRAY_SIZE(commands); ++i)
		printf("  %s %s\n", ARGV[0], commands[i].usage);
}

static int global_options(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"version", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;

	while ((option = getopt_long(argc, argv, "vh", long_options, &option_index)) != -1) {
		switch (option) {
			case 'v':
				version();
				return 0;
			case 'h':
				version();
				printf("\n");
			case '?':
				help();
				return option == 'h';
		}
	}

	help();
	return 1;
}

static void expand_aliases(int *argc, char ***argv)
{
	int i;
	const char *alias = (*argv)[0];
	char **new_argv = NULL;
	int argv_alloced;
	int new_argc = 0;
	_cleanup_free_ char *config_name;

	xasprintf(&config_name, "alias.%s", alias);

	_cleanup_free_ char *alias_val = config_read_string(config_name);
	if (!alias_val)
		return;

	trim(alias_val);

	/* split commandline and prepend to argv */
	argv_alloced = 0;
	new_argv = xcalloc(*argc + 1, sizeof(*new_argv));

	char *tok = strtok(alias_val, " \t");
	while (tok) {
		if (new_argc >= argv_alloced) {
			argv_alloced += 16;
			new_argv = xreallocarray(new_argv,
				argv_alloced + *argc + 1, sizeof(*new_argv));
		}
		new_argv[new_argc++] = xstrdup(tok);
		tok = strtok(NULL, " \t");
	}

	/* copy in remaining items from argc */
	for (i=1; i < *argc; i++) {
		new_argv[new_argc++] = xstrdup((*argv)[i]);
	}
	new_argv[new_argc] = 0;
	*argv = new_argv;
	*argc = new_argc;
}

static int process_command(int argc, char *argv[])
{
	expand_aliases(&argc, &argv);

	for (size_t i = 0; i < ARRAY_SIZE(commands); ++i) {
		if (argc && !strcmp(argv[0], commands[i].name))
			return commands[i].cmd(argc, argv);
	}
	help();
	return 1;
}

static void load_saved_environment(void)
{
	_cleanup_free_ char *env = NULL;

	env = config_read_string("env");
	if (!env)
		return;

	for (char *tok = strtok(env, "\n"); tok; tok = strtok(NULL, "\n")) {
		char *equals = strchr(tok, '=');
		if (!equals || !*equals) {
			warn("The environment line '%s' is invalid.", tok);
			continue;
		}
		*equals = '\0';
		if (setenv(tok, equals + 1, true))
			warn_errno("The environment line '%s' is invalid.", tok);
	}
}

int main(int argc, char *argv[])
{
	/* For process.h to function. */
	ARGC = argc;
	ARGV = argv;

	/* Do not remove this umask. Always keep at top. */
	umask(0077);

	load_saved_environment();

	if (argc >= 2 && argv[1][0] != '-')
		return process_command(argc - 1, argv + 1);

	return global_options(argc, argv);
}
