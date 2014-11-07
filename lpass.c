/*
 * Copyright (c) 2014 LastPass.
 *
 *
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
	CMD(export)
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

static int process_command(int argc, char *argv[])
{
	for (size_t i = 0; i < ARRAY_SIZE(commands); ++i) {
		if (!strcmp(argv[0], commands[i].name))
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
