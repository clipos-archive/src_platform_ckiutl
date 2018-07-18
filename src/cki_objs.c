// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2010-2018 ANSSI. All Rights Reserved.
#include "ckiutl.h"

int cki_getkeys(ckitoken* tok) {
  int rc = 0;
  unsigned int nkeys;
  PKCS11_KEY *privatekeys;

  rc = PKCS11_enumerate_keys(tok->slot->token, &privatekeys, &nkeys);
  if (rc) {
    _WARN("PKCS11_enumerate_keys failed\n");
    return CKI_ERR_UNKNOWN;
  }
  
  tok->keys = privatekeys;
  tok->nkeys = nkeys;

  return CKI_RET_OK;

}


int cki_getcerts(ckitoken* tok) {
  int rc, ret;
  PKCS11_CERT *certs;
  unsigned int ncerts;

  _DEBUG("reading certificates on card\n");

  // get all certs on token
  rc = PKCS11_enumerate_certs(tok->slot->token, &certs, &ncerts);
  if (rc) {
    _WARN("PKCS11_enumerate_certs failed\n");
    ret = CKI_ERR_CERT; goto get_failed;
  }
  if (ncerts <= 0) {
    _WARN("no certificates found\n");
    ret = CKI_ERR_CERT; goto get_failed;
  }

  tok->certs = certs;
  tok->ncerts = ncerts;

  return CKI_RET_OK;

 get_failed:
  return ret;
  
}

int cki_selectcert(ckitoken* tok, const char* label) {
  int ret, i, found = 0;
  PKCS11_CERT *cert;

  _DEBUG("requesting certificate %s\n", label);

  if(!tok->certs) {
    _WARN("no certificates\n");
    ret = CKI_ERR_CERT; goto select_failed;
  }

  // search for matching cert
  for(i=0;i<tok->ncerts && !found;i++) {
    cert = &tok->certs[i];
    found = !strncmp(cert->label, label, MAX_LABEL_LEN);
  }

  if(!found) {
    _WARN("certificate not found\n");
    ret = CKI_ERR_CERT; goto select_failed;
  }
  
  tok->cert = cert;
  return CKI_RET_OK;

 select_failed:
  return ret;
}

int
do_showcontent(ckitoken *tok)
{
  int rc = 0, i = 0;
  PKCS11_CERT *cert = NULL;
  PKCS11_KEY *key = NULL;
  char subject[CERTPARAMSIZE];
  char issuer[CERTPARAMSIZE];

  _DEBUG("Listing certificates\n");

  if(!tok->certs) {
    _WARN("no certificates\n");
    return CKI_ERR_CERT;
  }

  printf("==== Certificates ====\n");

  for(i=0; i<tok->ncerts; i++) {
    cert = &tok->certs[i];
    
    printf("Label : %s\n", cert->label);
    printf("  id : %s\n", hexDump((char*)cert->id, cert->id_len));
    printf("  len : %d\n", cert->id_len);
    if(cert->x509 == NULL) {
      printf("null cert\n");
    }

    X509_check_ca (cert->x509);
    X509_NAME_oneline (X509_get_subject_name (cert->x509), subject, CERTPARAMSIZE);
    X509_NAME_oneline (X509_get_issuer_name (cert->x509), issuer, CERTPARAMSIZE);
    printf ("  Subject : %s\n", subject);
    printf ("  Issuer : %s\n", issuer);
    printf ("  KeyUsage :\n");
    print_keyUsage (cert->x509->ex_kusage);
    printf ("\n");
  }

  printf("==== Keys ====\n");

  rc = cki_getkeys(tok);
  if(rc) {
    _ERROR("Error while retrieving keys");
    return rc;
  }

  for(i=0; i < tok->nkeys; i++) {
    key=&tok->keys[i];
    
    printf("Label : %s\n", key->label);
    printf("  id : %s\n", hexDump((char*)key->id, key->id_len));
    printf("  len : %d\n", key->id_len);
    printf("  private : %d\n", key->isPrivate);
    printf("  needLogin : %d\n", key->needLogin);
  }

  return CKI_RET_OK;
}


int
do_generaterandom(ckitoken *tok, const unsigned int nb_bytes)
{
  int i, rc = 0, ret = CKI_RET_OK;
  unsigned char *res = NULL;

  _DEBUG("Generating %u random bytes\n", nb_bytes);

  if(nb_bytes == 0) { goto leave_generaterandom; }
  
  res = (unsigned char*)malloc(nb_bytes * sizeof(char));
  if(res == NULL) {
    _ERROR("Failed to allocate random bytes buffer\n");
    ret = CKI_ERR_MEM;
    goto leave_generaterandom;
  }
  
  rc = PKCS11_generate_random(tok->slot, res, nb_bytes);
  if (rc) {
    _WARN("PKCS11_generate_random failed\n");
    ret = CKI_ERR_UNKNOWN;
    goto leave_generaterandom;
  }

  for(i = 0; i < nb_bytes; ++i) {
    printf("%c", res[i]);
  }


 leave_generaterandom:

  if(res) { free(res); }

  return ret;
}
