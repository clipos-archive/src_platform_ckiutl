// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2010-2018 ANSSI. All Rights Reserved.
/* 
 *  protos.h - ckiutl global prototypes
 *  Copyright (C) 2010 SGDSN/ANSSI
 *  Author: Benjamin Morin <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _PROTOS_H
#define _PROTOS_H

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_PIN_LEN 16
#define MAX_LABEL_LEN 32
#define MAX_TEXT_LEN 256
#define MAX_SIG_LEN 256

#define _WARN(fmt, args...) fprintf(stderr, "Warning (%s): " fmt, \
				    __FUNCTION__, ## args)  
#define _ERROR(fmt, args...) fprintf(stderr, "Error (%s): " fmt, \
				     __FUNCTION__, ## args)  
#define _DEBUG(fmt, args...) fprintf(stderr, "Debug (%s): " fmt, \
				     __FUNCTION__, ## args)  

extern const char *g_modulepath;
extern const char *g_label;
extern const char *g_pin;
extern const char *g_envvar;
extern const char *g_cacertpath;
extern int g_debug;

#endif /* _PROTOS_H */
