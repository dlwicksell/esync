/*
* Package:       esync
* File:          esyncd.c
* Summary:       Keeps a GT.M secondary environment synced with a primary
* Maintainer:    David Wicksell
* Last Modified: Sep 5, 2014
*
* Written by David Wicksell <dlw@linux.com>
* Copyright © 2010-2014 Fourth Watch Software, LC
*
* This program is free software: you can redistribute it and/or modify it
* under the terms of the GNU Affero General Public License (AGPL) as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
* or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
* License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see http://www.gnu.org/licenses/.
*
*
* A program that will keep directories of mumps routines, etc., synced
* between a primary and a secondary GT.M instance.
*
* Need to add a local config file to allow local customizations and not
* force the daemon to use the $gtmroutines environment variable. 
*
* Need to add a queue and look at select(2) to make sure syncs happen
* reliably, as well as adding an option to recurse into directories.
*
* This daemon is deprecated now, as someone created a program that basically
* duplicates the core functionality, but they're further along, and have
* configuration files and a scripting language to configure it. It is called
* lsyncd, and is even in most of the repositories. Its scripting language is
* Lua though. Yuck! Maybe some day I should write a GT.M binding to esyncd,
* just for fun. I should also remember to implement a queue and possibly my
* own networking code, rather than relying on system calls. It would at
* least be a super fun project. :-)
*
* The lsyncd program has its own share of issues, so I'm going back to
* working on this project now.
*/


#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>


#define EVENT_SIZE sizeof(struct inotify_event)
#define BUF_LEN 1024 * (EVENT_SIZE + NAME_MAX + 1)
#define OPT_ARG ":h:u:"
#define PID_DIR "/var/run/"
#define PID_FILE "esyncd"
#define PID_SUFFIX ".pid"
/* Need to allow a configuration file and command line options, rather
   than hardcoding these calls to scp and ssh with system(3). */
#define CREATE_CMD "scp -p %s %s:%s/"
#define DELETE_CMD "ssh %s rm %s"


static int wd, fd;
static const char *user;
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t reopen_log = 0;


/* Print extra info to the terminal, if connected, log to syslog, then exit */
static void log_fprintf_exit(char *call)
{
  if (ttyname(STDERR_FILENO))
    fprintf(stderr, "%s\n", call);

  syslog(LOG_ERR, "%s\n", call);

  exit(EXIT_FAILURE);
}


/* Print error to the terminal, if connected, log to syslog, then exit */
static void log_perror_exit(char *call)
{
  if (ttyname(STDERR_FILENO))
    perror(call);

  syslog(LOG_ERR, "%s: %s: %s\n", user, call, strerror(errno));

  exit(EXIT_FAILURE);
}


/* No terminal, log to syslog, then exit */
static void log_exit(char *call)
{
  syslog(LOG_ERR, "%s: %s: %s\n", user, call, strerror(errno));

  exit(EXIT_FAILURE);
}


typedef struct queue_entry {
  struct queue_entry *next_ptr;
  struct inotify_event queue_ev;
} *queue_entry_t;

typedef struct queue_struct {
  struct queue_entry *head;
  struct queue_entry *tail;
} *queue_t;


queue_t queue_create()
{
  queue_t queue;

  queue = malloc(sizeof(struct queue_struct));

  if (! queue)
    log_exit("malloc queue");

  queue->head = queue->tail = NULL;

  return queue;
}


void queue_destroy(queue_t queue)
{
  if (queue) {
    while (queue->head) {
      queue_entry_t next = queue->head;
      queue->head = next->next_ptr;
      next->next_ptr = NULL;

      free(next);
    }

    queue->head = queue->tail = NULL;

    free(queue);
  }
}


void queue_enqueue(queue_entry_t entry, queue_t queue)
{
  entry->next_ptr = NULL;

  if (queue->tail) {
    queue->tail->next_ptr = entry;
    queue->tail = entry;
  } else {
    queue->head = queue->tail = entry;
  }
}


queue_entry_t queue_dequeue(queue_t queue)
{
  queue_entry_t first = queue->head;

  if (first) {
    queue->head = first->next_ptr;

    if (! queue->head)
      queue->tail = NULL;

    first->next_ptr = NULL;
  }

  return first;
}


int queue_empty(queue_t queue)
{
  return queue->head == NULL;
}


/* Catch signals, clean up, and reopen our log file when needed (logrotate) */
static void catch_intr(int signum)
{
  if (signum == SIGCHLD) {
    /* Can't do any I/O while trapping this signal */
    while (waitpid(-1, NULL, WNOHANG) > 0) /* No zombie = 0, no children = -1 */
      continue;
  } else if (signum == SIGHUP) {
    reopen_log = 1;
  } else {
    do {
      if (inotify_rm_watch(fd, wd) == -1)
        log_perror_exit("inotify_rm_watch");
    } while (--wd);

    if (close(fd) == -1)
      log_perror_exit("close watch");

    closelog();

    keep_running = 0;

    if (signum == SIGTERM)
      syslog(LOG_INFO, "Caught SIGTERM: Cleaning up.\n");
    else if (signum == SIGINT)
      syslog(LOG_INFO, "Caught SIGINT: Cleaning up.\n");
  } 
} 


int main(int argc, char *argv[]) 
{
  short int i, c;
  short int h_cnt, u_cnt;
  int flags;
  long int buflen, event_size, q_ev_size;
  int pid_fd;
  int sel_ret, ret;
  int plen, hlen, ulen;
  int flen, dlen, alen;
  char buf[BUF_LEN];
  char wr_buf[6]; /* PID size limit in Linux is 32768, which is 5 digits */
  char **dir;
  char *argstr = (char *) NULL;
  char *cmdstr = (char *) NULL;
  char *pid_path = (char *) NULL;
  const char *host = (char *) NULL;
  const struct hostent *hn;
  const struct passwd *pw = NULL;
  struct sigaction n_signal;
  struct inotify_event *event;
  mode_t mode;
  pid_t pid;
  pid_t cpid;
  queue_t q;
  queue_entry_t q_event;
  fd_set rfds;

  openlog(PID_FILE, LOG_PID, LOG_LOCAL0);

  if (getuid())
    log_fprintf_exit("You must run this program as root.");

  n_signal.sa_handler = catch_intr; 
  n_signal.sa_flags = 0;

  if (sigemptyset(&n_signal.sa_mask) == -1)
    log_perror_exit("sigemptyset");  

  if (sigaction(SIGCHLD, &n_signal, NULL) == -1)
    log_perror_exit("sigaction: initial SIGCHLD");  

  if (sigaction(SIGHUP, &n_signal, NULL) == -1)
    log_perror_exit("sigaction: SIGHUP");  

  if (sigaction(SIGTERM, &n_signal, NULL) == -1)
    log_perror_exit("sigaction: SIGTERM");  

  if (sigaction(SIGINT, &n_signal, NULL) == -1)
    log_perror_exit("sigaction: SIGINT");  

  /* Use h_cnt and u_cnt counters to ensure we have our mandatory args */
  opterr = h_cnt = u_cnt = 0;

  while ((c = getopt(argc, argv, OPT_ARG)) != -1) {
    switch (c) {
      case 'h':
        host = optarg;
        hn = gethostbyname(host);

        if (! hn)
          log_fprintf_exit("The -h argument requires a valid hostname.");

        ++h_cnt;

        break;
      case 'u':
        user = optarg;
        pw = getpwnam(user);

        if (! strcmp(pw->pw_name, "root"))
          log_fprintf_exit("The -u flag cannot take root as an argument.");

        if (! pw)
          log_fprintf_exit("The -u argument requires a valid username.");

        ++u_cnt;

        break;
      case ':':
        if (ttyname(STDERR_FILENO))
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);

        syslog(LOG_ERR, "Option -%c requires an argument.\n", optopt);

        exit(EXIT_FAILURE);

        break;
      case '?':
        if (ttyname(STDERR_FILENO))
          fprintf(stderr, "Option -%c is not a valid option.\n", optopt);

        syslog(LOG_ERR, "Option -%c is not a valid option.\n", optopt);

        exit(EXIT_FAILURE);

        break;
    }
  }

  if (! h_cnt)
    log_fprintf_exit("You must supply a -h <host> option.");

  if (! u_cnt)
    log_fprintf_exit("You must supply a -u <user> option.");

  if (argc == optind)
    log_fprintf_exit("You must supply at least one directory.");


  /* Turning myself into a daemon */
  if ((pid = fork()) == -1)
    log_perror_exit("pid fork");
  
  if (pid > 0) {
    plen = strlen(PID_DIR) + strlen(PID_FILE) + strlen(PID_SUFFIX); 
    ulen = strlen(user); 
  
    pid_path = (char *) malloc(plen + ulen + 2); /* 2 for "-" and EOL */
  
    if (! pid_path)
      log_perror_exit("malloc pid_path");
  
    if (sprintf(pid_path, "%s%s-%s%s", PID_DIR, PID_FILE, user, PID_SUFFIX) < 0)
      log_perror_exit("sprinf pid_path");
  
    if (sprintf(wr_buf, "%d", pid) < 0)
      log_perror_exit("sprintf pid");

    flags = O_WRONLY | O_CREAT | O_EXCL;
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    if ((pid_fd = open(pid_path, flags, mode)) == -1) {
      /* Can't write child PID, so we kill the child and exit */
      if (kill(pid, SIGKILL) == -1)
        log_perror_exit("kill child process failed");

      log_perror_exit("open pid_path");
    }

    /* Need to write our PID in /var/run/esyncd-<env>.pid for init */
    if (write(pid_fd, wr_buf, strlen(wr_buf)) == -1)
      log_perror_exit("write pid");

    if (close(pid_fd) == -1)
      log_perror_exit("close pid");

    free(pid_path); /* Need to free pid_path for parent */
    pid_path = (char *) NULL;

    exit(EXIT_SUCCESS);
  } /* End of parent process, child process continues */

  free(pid_path); /* Need to free pid_path for child */
  pid_path = (char *) NULL;

  /* Shedding root privileges and becoming instance */
  if (setuid(pw->pw_uid) == -1)
    log_perror_exit("setuid");
    
  if (chdir(pw->pw_dir) == -1)
    log_perror_exit("chdir");

  /* Standard daemonization includes closing the standard file descriptors */
  if (close(STDIN_FILENO) == -1)
    log_perror_exit("close STDIN");

  if (close(STDOUT_FILENO) == -1)
    log_perror_exit("close STDOUT");

  if (close(STDERR_FILENO) == -1)
    log_perror_exit("close STDERR");

  /* Need dir so we know which directory our event happened in */
  dir = (char **) calloc(argc - optind + 1, sizeof(char *)); 

  if (! dir)
    log_exit("calloc dir");

  if ((fd = inotify_init()) == -1)
    log_exit("inotify_init");

  q = queue_create();

  for (i = optind; i < argc; ++i) {
    if ((wd = inotify_add_watch(fd, argv[i], IN_CREATE | IN_DELETE)) == -1)
      log_exit("inotify_add_watch");

    dir[wd] = argv[i];
  }

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  /* Main loop */
  while (keep_running) {
    /* Reopen the logfile after it has been rotated */
    if (reopen_log) {
      closelog();

      openlog(PID_FILE, LOG_PID, LOG_LOCAL0);

      reopen_log = 0;
    }

    /* Consider using a more modern way of synchronous I/O than select(2) */
    sel_ret = select(FD_SETSIZE, &rfds, NULL, NULL, NULL);

    /* I really hate this sleep call. I need to figure out why I lose
       events coming out of the inotify service. I might need to add
       a queue here also. Still, this is a bad hack. */

    sleep(1); /* Let events build if coming from a fast loop */
    
    if (sel_ret == -1) {
      if (errno != 4) /* Interrupted system call caused by SIGCHLD */
        syslog(LOG_ERR, "%s: select intr: %s\n", user, strerror(errno));

      continue;
    } else {
      /* read up to 1024 events into buf */
      buflen = read(fd, buf, BUF_LEN);

      if (buflen == -1) {
        if (errno != 4) /* Interrupted system call caused by SIGCHLD */
          syslog(LOG_ERR, "%s: read intr: %s\n", user, strerror(errno));

        continue;
      }
    }

    /* Create a child to sync the routines, then go back to the select */
    if ((cpid = fork()) == -1)
      log_exit("cpid fork");

    if (cpid > 0)
      continue;

    /* Need to turn off signal handling for SIGCHLD for the children */
    n_signal.sa_handler = SIG_DFL; /* Default is to SIG_IGN */

    if (sigaction(SIGCHLD, &n_signal, NULL) == -1)
      log_exit("sigaction: SIGCHLD");  

    i = 0;
    while (i < buflen) {
      /* Pick up one event at a time */
      event = (struct inotify_event *) &buf[i];

      /* Only care about new files being created, modified, or deleted */
      if (event->len && (event->mask & (IN_CREATE | IN_DELETE))) {
        dlen = strlen(dir[event->wd]);
        flen = strlen(event->name);

        /* Don't care about certain files; *.o, .*, #* */
        if (! ((event->name[flen-2] == '.' && event->name[flen-1] == 'o')
            || event->name[0] == '.' || event->name[0] == '#')) {
          event_size = offsetof(struct inotify_event, name) + event->len;
          q_ev_size = offsetof(struct queue_entry, queue_ev.name) + event->len;

          argstr = (char *) malloc(dlen + flen + 2);

          if (! argstr)
            log_exit("malloc argstr");

          if (sprintf(argstr, "%s/%s", dir[event->wd], event->name) < 0)
            log_exit("sprintf argstr");

          alen = strlen(argstr);
          hlen = strlen(host); 

          if (event->mask & IN_CREATE) {
            /* Different command if a file is created or modified */
            cmdstr = (char *) malloc(strlen(CREATE_CMD) + alen + hlen + dlen);

            if (! cmdstr)
              log_exit("malloc cmdstr IN_CREATE");

            if (sprintf(cmdstr, CREATE_CMD, argstr, host, dir[event->wd]) < 0)
              log_exit("sprintf cmdstr IN_CREATE");
          } else {
            /* Different command if a file is deleted */
            cmdstr = (char *) malloc(strlen(DELETE_CMD) + alen + hlen);

            if (! cmdstr)
              log_exit("malloc cmdstr IN_DELETE");

            if (sprintf(cmdstr, DELETE_CMD, host, argstr) < 0)
              log_exit("sprintf cmdstr IN_DELETE");
          }

          /* Doing the actual syncing of the routines to the secondary */
          if ((ret = system(cmdstr)) == -1) {
            log_exit("system");
          } else {
            if (WEXITSTATUS(ret)) {
              if (event->mask & IN_CREATE) {
                syslog(LOG_ERR, "%s: scp error %d, copying %s\n", user,
                    WEXITSTATUS(ret), argstr);

                exit(EXIT_FAILURE);
              } else {
                syslog(LOG_ERR, "%s: ssh error %d, removing %s\n", user,
                    WEXITSTATUS(ret), argstr);

                exit(EXIT_FAILURE);
              }
            } else {
              if (event->mask & IN_CREATE)
                syslog(LOG_INFO, "copied %s to %s\n", argstr, host);
              else
                syslog(LOG_INFO, "removed %s from %s\n", argstr, host);
            }
          }

          free(argstr);
          argstr = (char *) NULL;

          free(cmdstr);
          cmdstr = (char *) NULL;
        }
      }

      i += EVENT_SIZE + event->len; /* Move to the next event in the buffer */
    }

    keep_running = 0; /* Kill children, parent needs signal to get here */
  }

  free(dir);

  exit(EXIT_SUCCESS);
}
