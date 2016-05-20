#include "util.h"
#include "log.h"
#include "config.h"
#include <fcntl.h>
#include <sys/time.h>

#define TIME_FMT "%lld.%06lld"
#define TIME_ARGS(tv) ((long long)(tv)->tv_sec), ((long long)(tv)->tv_usec)

int lpass_log_level()
{
	char *log_level_str;
	int level;

	log_level_str = getenv("LPASS_LOG_LEVEL");
	if (!log_level_str)
		return LOG_NONE;

	level = strtoul(log_level_str, NULL, 10);
	return (enum log_level) level;
}

void lpass_log(enum log_level level, char *fmt, ...)
{
	struct timeval tv;
	struct timezone tz;
	va_list ap;
	_cleanup_fclose_ FILE *fp;

	int req_level = lpass_log_level();

	if (req_level < level)
		return;

	fp = lpass_log_open();
	if (!fp)
		return;

	gettimeofday(&tv, &tz);
	fprintf(fp, "<%d> [" TIME_FMT "] ", level, TIME_ARGS(&tv));
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
}

FILE *lpass_log_open()
{
	_cleanup_free_ char *upload_log_path = NULL;

	if (lpass_log_level() < 0)
		return NULL;

	upload_log_path = config_path("lpass.log");
	return fopen(upload_log_path, "a");
}
