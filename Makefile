#
# Package:       esync
# File:          Makefile
# Summary:       Makefile for the esync daemon
# Maintainer:    David Wicksell
# Last Modified: Sep 5, 2014
#
# Written by David Wicksell <dlw@linux.com>
# Copyright © 2010-2014 Fourth Watch Software, LC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License (AGPL)
# as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# This Makefile is written to be run in a Red Hat environment
# Tweaks maybe needed for other distributions
#


CC = gcc
CFLAGS = -O2 -Wall #-g
SRCS = esyncd.c
OBJS = esyncd.o
PROG = esyncd

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(PROG)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS)

install: $(PROG)
	@if [ "$${USER}" != "root" ]; then \
	  echo "You must install this program as root."; \
	  exit 1; \
	fi

	install -o root -g root -m 755 $(PROG) /usr/local/bin/

clean:
	rm -f $(OBJS) $(PROG)

.PHONY: install
