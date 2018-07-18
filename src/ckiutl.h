// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2010-2018 ANSSI. All Rights Reserved.
#ifndef _CKIUTL_H
#define _CKIUTL_H

#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "protos.h"
#include <libp11.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define CKI_RET_OK 0x0000
#define CKI_ERR_MODULE 0x0001
#define CKI_ERR_SLOT 0x0002
#define CKI_ERR_TOKEN 0x0003
#define CKI_ERR_CERT 0x0004
#define CKI_ERR_LOGIN 0x0005
#define CKI_ERR_MEM 0x0006
#define CKI_ERR_IO 0x0007
#define CKI_ERR_INIT 0x0008
#define CKI_ERR_KEY 0x0009
#define CKI_ERR_UNKNOWN 0x000A
#define CKI_ERR_MISSPARAM 0x000B
#define CKI_ERR_BADPARAM 0x000B

#define CERTPARAMSIZE 256
#define SIGLEN 256

typedef struct _ckitoken {
  PKCS11_CTX *ctx;

  PKCS11_SLOT *slots;
  PKCS11_SLOT *slot;
  unsigned int nslots;

  PKCS11_CERT *certs;
  PKCS11_CERT *cert;
  unsigned int ncerts;

  PKCS11_KEY *keys;
  unsigned int nkeys;

} ckitoken;

// misc functions

char *hexDump(char* string, size_t len);
ssize_t read_data(FILE* file, unsigned char* buffer);
void print_keyUsage (unsigned long keyUsage);
/*
static inline int _read(int fd, unsigned char *buf, size_t len);
static inline int _write(int fd, unsigned char *buf, size_t len);
*/

// Session management stuff
ckitoken* cki_newtok();
int cki_deltok(ckitoken* tok);
int cki_init(ckitoken* tok, const char* modulepath);
int cki_login(ckitoken* tok, const char* pin);
int cki_changepin(ckitoken* tok, const char* oldpin, const char *newpin);
int do_changepin(ckitoken* tok);

// Encryption and decryption related stuff
int cki_decrypt(ckitoken* tok, const unsigned char* ciphertext, const size_t ciphertextlen, unsigned char** plaintext, size_t* plaintextlen);
int do_decrypt(ckitoken *tok, const char* cert_label);
int cki_encrypt(ckitoken* tok, const unsigned char* plaintext, const size_t plaintextlen, unsigned char** ciphertext, size_t* ciphertextlen);
int do_encrypt(ckitoken *tok, const char* cert_label);
int cki_sign(ckitoken* tok, const unsigned char* message, const size_t messagelen, unsigned char** signature, size_t* signaturelen);
int cki_verify(ckitoken* tok, unsigned char* message, size_t messagelen, unsigned char* signature, size_t signaturelen);
int do_sign(ckitoken *tok, const char* cert_label);
int do_verify(ckitoken* tok, const char* message_filename, const char* sig_filename, const char* cert_label);

// Object (certificates, keys, ...) selection stuff...
int cki_getkeys(ckitoken* tok);
int cki_getcerts(ckitoken* tok);
int cki_selectcert(ckitoken* tok, const char* label);
int do_showcontent(ckitoken *tok);
int do_generaterandom(ckitoken *tok, const unsigned int nb_bytes);

#endif // _CKIUTL_H
