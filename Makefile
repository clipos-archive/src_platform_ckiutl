# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2010-2018 ANSSI. All Rights Reserved.
CKIUTL := ckiutl

SRCPATH := src
HDRS := ckiutl.h protos.h
SRCLIB := cki_objs.c cki_session.c cki_cipher.c ckiutl.c cki_utils.c

CC := gcc
CFLAGS := -O2 -Wall -I${SRCPATH} ${CFLAGS}
LDFLAGS := -lcrypto -lssl -lp11 ${LDFLAGS}

HDRS := ${HDRS:%=${SRCPATH}/%}
SRCLIB := ${SRCLIB:%=${SRCPATH}/%}
OBJLIB := ${SRCLIB:%.c=%.o}
CKIUTLLIB := ${CKIUTL:%=%.a}
CKIUTLLIB := ${CKIUTLLIB:%=${SRCPATH}/%}

all: ${CKIUTL}

${CKIUTL}: Makefile ${SRCPATH}/ckiutl.o ${CKIUTLLIB}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${SRCPATH}/ckiutl.o ${CKIUTLLIB}

${CKIUTLLIB}: ${OBJLIB}
	@echo "Creating archive:"
	ar rcs $@ ${OBJLIB}

.c.o:
	@echo "Compiling " $@
	${CC} ${CFLAGS} -c $< -o $@ 

${SRCLIB} ${CKIUTL}.c: ${HDRS}

clean:
	rm -f ${CKIUTL}
	rm -f src/*.o
	rm -f src/*.a
	rm -f src/*~

testmake:
	@echo ${SRCLIB}
	@echo ${OBJLIB}
	@echo ${CKIUTLLIB}
