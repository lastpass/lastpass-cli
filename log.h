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
	LOG_LEVEL_NONE = -1,
	LOG_LEVEL_ERROR = 3,
	LOG_LEVEL_WARNING = 4,
	LOG_LEVEL_INFO = 6,
	LOG_LEVEL_DEBUG = 7,
	LOG_LEVEL_VERBOSE = 8,	/* _everything_ including CURL verbose logs */
};

int lpass_log_level();
int lpass_log_is_verbose();
int lpass_log_is_debug();
int lpass_log_is_info();
int lpass_log_is_warning();
int lpass_log_is_error();
int lpass_log_is_none();
void lpass_log(enum log_level level, char *fmt, ...);
FILE *lpass_log_open();

#define LOG0(level, fmt)      (lpass_log(level, "%s:%d:%s: " fmt, __FILE__, __LINE__, __func__))
#define LOG(level, fmt, ...)  (lpass_log(level, "%s:%d:%s: " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__))

#define LOG_VERBOSE0(fmt)      if (lpass_log_is_verbose()) LOG0(LOG_LEVEL_VERBOSE, fmt)
#define LOG_VERBOSE(fmt, ...)  if (lpass_log_is_verbose()) LOG(LOG_LEVEL_VERBOSE, fmt, __VA_ARGS__)

#define LOG_DEBUG0(fmt)      if (lpass_log_is_debug()) LOG0(LOG_LEVEL_DEBUG, fmt)
#define LOG_DEBUG(fmt, ...)  if (lpass_log_is_debug()) LOG(LOG_LEVEL_DEBUG, fmt, __VA_ARGS__)

#define LOG_INFO0(fmt)      if (lpass_log_is_info()) LOG0(LOG_LEVEL_INFO, fmt)
#define LOG_INFO(fmt, ...)  if (lpass_log_is_info()) LOG(LOG_LEVEL_INFO, fmt, __VA_ARGS__)

#define LOG_WARNING0(fmt)      if (lpass_log_is_warning()) LOG0(LOG_LEVEL_WARNING, fmt)
#define LOG_WARNING(fmt, ...)  if (lpass_log_is_warning()) LOG(LOG_LEVEL_WARNING, fmt, __VA_ARGS__)

#define LOG_ERROR0(fmt)      if (lpass_log_is_error()) LOG0(LOG_LEVEL_ERROR, fmt)
#define LOG_ERROR(fmt, ...)  if (lpass_log_is_error()) LOG(LOG_LEVEL_ERROR, fmt, __VA_ARGS__)

#endif
