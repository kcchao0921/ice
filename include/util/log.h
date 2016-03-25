#ifndef UTIL_LOG_H_
#define UTIL_LOG_H_

#include <stdio.h>
#include <sys/syslog.h>

#define LOG_LEVEL_DEBUG		1
#define LOG_LEVEL_INFO		2
#define LOG_LEVEL_ERROR		3
#define LOG_LEVEL_FATAL		4

#ifndef LOG_LEVEL
#define LOG_LEVEL	LOG_LEVEL_DEBUG
#endif

#if (LOG_LEVEL <= LOG_LEVEL_DEBUG)
#define DEBUG(...)	 syslog(LOG_DEBUG, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#if (LOG_LEVEL <= LOG_LEVEL_INFO)
#define INFO(...)	 syslog(LOG_INFO, __VA_ARGS__)
#else
#define INFO(...)
#endif

#if (LOG_LEVEL <= LOG_LEVEL_ERROR)
#define ERROR(...)	 syslog(LOG_ERR, __VA_ARGS__)
#else
#define ERROR(...)
#endif

#if (LOG_LEVEL <= LOG_LEVEL_FATAL)
#define FATAL(...)	 syslog(LOG_CRIT, __VA_ARGS__)
#else
#define FATAL(...)
#endif

#endif
