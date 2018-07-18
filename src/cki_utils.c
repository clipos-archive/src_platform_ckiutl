// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2010-2018 ANSSI. All Rights Reserved.
#include "ckiutl.h"

char *hexDump(char* string, size_t len) {
  char * res = NULL;
  int i;

  res = malloc(len*2+1);

  for(i=0;i<len;i++)
    sprintf(res+2*i,"%02X", string[i]&0xFF);

  return res;
}

ssize_t
read_data(FILE* file, unsigned char* buffer)
{
  char buf[16];
  size_t numread;
  ssize_t total = 0;

  while(1) {
    numread = fread (buf, 1, 16, file);
    if (numread == 0) {
      if (feof (file))
	return total;
      else {
	perror("error while reading data");
	return -1;
      }
    }

    if(total + numread > MAX_TEXT_LEN)
      return -1;

    memcpy(buffer + total, buf, numread);
    total += numread;
    if (numread < 16)
      return total;
  }
}

#define pu(ku,val,str) do {				\
  if ((ku & val) == val) printf ("  %s\n", str);        \
} while (0)

void print_keyUsage (unsigned long keyUsage) {
  pu (keyUsage, KU_DIGITAL_SIGNATURE, "Digital Signature");
  pu (keyUsage, KU_NON_REPUDIATION, "Non Repudiation");
  pu (keyUsage, KU_KEY_ENCIPHERMENT, "Key Encipherment");
  pu (keyUsage, KU_DATA_ENCIPHERMENT, "Data Encipherment");
  pu (keyUsage, KU_KEY_AGREEMENT, "Key Agreement");
  pu (keyUsage, KU_KEY_CERT_SIGN, "Cert Sign");
  pu (keyUsage, KU_CRL_SIGN, "CRL Sign");
  pu (keyUsage, KU_ENCIPHER_ONLY, "Encipher Only");
  pu (keyUsage, KU_DECIPHER_ONLY, "Decipher Only");
}

/*
static inline int 
_read(int fd, unsigned char *buf, size_t len)
{
        ssize_t rlen;
        unsigned char *ptr = buf;
        size_t remaining = len;

        for (;;) {
                rlen = read(fd, ptr, remaining);
                if (rlen < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("read");
                        return -1;
                }
                ptr += rlen;
                remaining -= rlen;
                if (!remaining)
                        break;
        }
        return 0;
}

static inline int
_write(int fd, unsigned char *buf, size_t len)
{
        ssize_t wlen;
        unsigned char *ptr = buf;
        size_t remaining = len;

        for (;;) {
                wlen = write(fd, buf, remaining);
                if (wlen < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("write");
                        return -1;
                }
                ptr += wlen;
                remaining -= wlen;
                if (!remaining)
                        break;
        }
        return 0;
}
*/
