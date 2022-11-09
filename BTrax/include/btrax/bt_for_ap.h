/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_for_ap.h - branch trace start/stop function for application           */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2008                         */
/*             Authors: Yumiko Sugita (yumiko.sugita.yf@hitachi.com),        */
/*                      Satoshi Fujiwara (sa-fuji@sdl.hitachi.co.jp)         */
/*                                                                           */
/*  This program is free software; you can redistribute it and/or modify     */
/*  it under the terms of the GNU General Public License as published by     */
/*  the Free Software Foundation; either version 2 of the License, or        */
/*  (at your option) any later version.                                      */
/*                                                                           */
/*  This program is distributed in the hope that it will be useful,          */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            */
/*  GNU General Public License for more details.                             */
/*                                                                           */
/*  You should have received a copy of the GNU General Public License        */
/*  along with this program; if not, write to the Free Software              */
/*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111 USA      */
/*****************************************************************************/

#ifndef __BT_FOR_AP_H__
#define __BT_FOR_AP_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>	// for O_WRONLY
#include <unistd.h>
#include <signal.h>

#define BT_MAX_BUF_LEN	4096

#ifdef BT_STOP_ERROR
#  define dprintf(...)	
#else
#  define dprintf(...)	fprintf(__VA_ARGS__)
#endif

typedef void (*sighandler_t)(int);

static void bt_sigchld_ignore(int signum)
{
}
static int bt_exec_system(char *cmd)
{
	sighandler_t h;

	h = signal(SIGCHLD, bt_sigchld_ignore);
	if (system(cmd) < 0) {
		//dprintf(stderr, "BTRAX: system call failed.\n");
		//signal(SIGCHLD, h);
		return -1;
	}
	signal(SIGCHLD, h);
	return 0;
}

static int bt_format_cmd_and_exec(char *fmt, ...)
{
	va_list argp;
	char cmd[BT_MAX_BUF_LEN];
	int len;

	va_start(argp, fmt);
	len = vsnprintf(cmd, BT_MAX_BUF_LEN, fmt, argp);
	va_end(argp);
	if (len == BT_MAX_BUF_LEN) {
		//dprintf(stderr, "BTRAX: BT_MAX_BUF_LEN is too short.\n");
		return -1;
	}
	return bt_exec_system(cmd);
}

static int bt_write_enable(int enable)
{
	int fd;
	char *s;

	fd = open("/proc/btrax/enable", O_WRONLY);
	if (fd < 0)
		return -1;
	s = enable ? "1\n" : "0\n";
	write(fd, s, 2);
	close(fd);
	return 0;
}

static inline void __bt_start_from_ap(pid_t pid, char *syscall_ids)
{
	char *outdir, out[BT_MAX_BUF_LEN];
	struct stat st;
	int rc;

	if (stat("/proc/btrax/enable", &st) < 0) {
		//dprintf(stderr,
		//	"BTRAX: btrax not loaded, or permission denied\n");
		return;
	}
	if (!(outdir = getenv("BT_OUTPUT_DIR"))) {
		//dprintf(stderr, "BTRAX: can't get 'BT_OUTPUT_DIR' value\n");
		return;
	}
	/* Since btrax stores the application's map information in the log file,
	 * we do not save $PID.maps.
	 */
	if (bt_format_cmd_and_exec("echo %d > /proc/btrax/pid", pid) < 0)
		return;
	if (syscall_ids) {
		rc = snprintf(out, BT_MAX_BUF_LEN,
			      "echo %s > /proc/btrax/filter_syscall",
			      syscall_ids);
		if (rc >= BT_MAX_BUF_LEN) {
			//dprintf(stderr, "BTRAX: BT_MAX_BUF_LEN is too short\n");
			return;
		}
		bt_exec_system(out);
	}
	bt_write_enable(1);
}

void bt_start_from_ap(void)
{
	__bt_start_from_ap(getpid(), NULL);
}

void bt_stop_from_ap(void)
{
	bt_write_enable(0);
}

#if 0
void bt_start_syscall_chk(int n, ...)
{
	va_list argp;
	char *p, tmp[BT_MAX_BUF_LEN];
	int i, rc, left;

	p = tmp;
	left = BT_MAX_BUF_LEN;

	va_start(argp, n);
	for (i = 0; i < n; i++) {
		rc = snprintf(p, left, "%d,", va_arg(argp, int));
		if (rc >= left) {
			dprintf(stderr,
				"BTRAX: BT_MAX_BUF_LEN is too short\n");
			return;
		}
		p += rc;
		left -= rc;
	}
	/* delete last ',' character */
	p--;
	*p = '\0';
	va_end(argp);

	__bt_start_from_ap(getpid(), tmp, 0);
}
#endif

#define BT_COLLECT_NAME	"bt_collect_log"
void bt_term_from_ap(void)
{
	if (bt_write_enable(0) < 0) {
		if (seteuid(getuid()) < 0)
			return;
		if (bt_write_enable(0) < 0)
			return;
	}
	bt_exec_system("(pid=`ps -u root|grep " BT_COLLECT_NAME \
		       "|sort -n|head -n 1|awk '{print $1}'`; kill $pid)");
}

#endif /*__BT_FOR_AP_H__*/
