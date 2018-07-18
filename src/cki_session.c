// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2010-2018 ANSSI. All Rights Reserved.
#include "ckiutl.h"

ckitoken* cki_newtok() {
  ckitoken* t = NULL;

  t = (ckitoken*)malloc(sizeof(ckitoken));
  if(!t) {
    _ERROR("Could not create new token");
    return NULL;
  }

  t->ctx = NULL;
  t->slots = NULL;
  t->nslots = 0;
  t->slot = NULL;
  t->certs = NULL;
  t->ncerts = 0;
  t->keys = NULL;
  t->nkeys = 0;

  return t;
}

int cki_deltok(ckitoken* tok) {
  if(!tok->ctx)
    return CKI_RET_OK;

  if(tok->slots)
    PKCS11_release_all_slots(tok->ctx, tok->slots, tok->nslots);
  
  PKCS11_CTX_unload(tok->ctx);
  PKCS11_CTX_free(tok->ctx);

  return CKI_RET_OK;
}

int cki_init(ckitoken* tok, const char* modulepath) {
  PKCS11_CTX *ctx;
  PKCS11_SLOT *slots, *slot;
  unsigned int nslots;
  int rc,ret;

  if(!tok) {
    _ERROR("NULL token");
    return CKI_ERR_INIT;
  }
  if(!modulepath) {
    _ERROR("NULL module path");
    return CKI_ERR_MODULE;
  }

  ctx = PKCS11_CTX_new();
  
  // load pkcs #11 module
  rc = PKCS11_CTX_load(ctx, modulepath);
  if (rc) {
    _ERROR("loading pkcs11 engine failed: %s\n", ERR_reason_error_string(ERR_get_error()));
    ret = CKI_ERR_MODULE; goto init_nolib;
  }
  
  // get information on all slots
  rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
  if (rc < 0) {
    _WARN("no slots available\n");
    ret = CKI_ERR_SLOT; goto init_noslots;
  }

  // get first slot with a token
  slot = PKCS11_find_token(ctx, slots, nslots);
  if (!slot || !slot->token) {
    _WARN("no token available\n");
    ret = CKI_ERR_TOKEN; goto init_notoken;
  }

  tok->ctx = ctx;
  tok->slots = slots;
  tok->nslots = nslots;
  tok->slot = slot;

  return CKI_RET_OK;

 init_notoken:
  PKCS11_release_all_slots(ctx, slots, nslots);
 init_noslots:
  PKCS11_CTX_unload(ctx);
 init_nolib:
  PKCS11_CTX_free(ctx);

  return ret;
}

// perform pkcs#11 login

int cki_login(ckitoken* tok, const char* pin) {
  int rc;

  _DEBUG("logging in with pin %s\n", pin);

  if(!tok || !tok->slot) {
    _ERROR("Token no initialized");
    return CKI_ERR_INIT;
  }
  if(!pin) {
    _ERROR("Null PIN");
    return CKI_ERR_BADPARAM;
  }
  if(strnlen(pin, MAX_PIN_LEN) >= MAX_PIN_LEN) {
    _ERROR("PIN absent or malformed\n");
    return CKI_ERR_BADPARAM;
  }

  rc = PKCS11_login(tok->slot, 0, pin);

  // TODO : forget pin

  if (rc)
    return CKI_ERR_LOGIN;

  return CKI_RET_OK;
}

int
cki_changepin(ckitoken* tok, const char* oldpin, const char *newpin)
{
  int ret = 0;
  // TODO
  return ret;
}

int
do_changepin(ckitoken* tok) {
  int ret = 0;
  // TODO
  return ret;
}

