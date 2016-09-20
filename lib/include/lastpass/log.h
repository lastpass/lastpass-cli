#ifndef __LOG_H
#define __LOG_H

/*
 * Loglevels for ~/.lpass/lpass.log.  By default, nothing is logged, but
 * setting LPASS_LOG_LEVEL to a positive value will turn on logging.
 *
 * NOTE: debug and verbose logs can include sensitive information such as
 *       session IDs in the clear.  Do NOT post logs in public without
 *       scrubbing them first!
 */
enum log_level
{
	LOG_NONE = -1,
	LOG_ERROR = 3,
	LOG_WARNING = 4,
	LOG_INFO = 6,
	LOG_DEBUG = 7,
	LOG_VERBOSE = 8,	/* _everything_ including CURL verbose logs */
};

int lpass_log_level();
void lpass_log(enum log_level level, char *fmt, ...);
FILE *lpass_log_open();

#endif
