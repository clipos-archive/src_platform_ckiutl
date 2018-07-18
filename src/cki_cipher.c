// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2010-2018 ANSSI. All Rights Reserved.
#include "ckiutl.h"

int
cki_encrypt(ckitoken* tok, 
	    const unsigned char* plaintext,
	    const size_t plaintextlen,
	    unsigned char** ciphertext,
	    size_t* ciphertextlen)
{
  EVP_PKEY *pubkey = NULL;
  unsigned char *encrypted = NULL;
  int len;
  int ret;

  _DEBUG("encrypting data...\n");

  if(!tok || !tok->cert) {
    _ERROR("could not get certificate\n");
    ret = CKI_ERR_CERT; goto encrypt_failed;
  }

  pubkey = X509_get_pubkey(tok->cert->x509);
  if (pubkey == NULL) {
    _ERROR("could not extract public key\n");
    ret = CKI_ERR_KEY; goto encrypt_failed;
  }

  encrypted = malloc(RSA_size(pubkey->pkey.rsa));
  if (!encrypted) {
    _ERROR("out of memory for encrypted data\n");
    ret = CKI_ERR_MEM; goto encrypt_failed;
  }

  len = RSA_public_encrypt(plaintextlen, plaintext, encrypted, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
  if (len < 0) {
    _ERROR("fatal: RSA_public_encrypt failed\n");
    ret = CKI_ERR_UNKNOWN; goto encrypt_freemem;
  }

  *ciphertext = encrypted;
  *ciphertextlen = len;

  return CKI_RET_OK;

 encrypt_freemem:
  free(encrypted);
 encrypt_failed:
  return ret;
  
}

int
cki_decrypt(ckitoken* tok,
	    const unsigned char* ciphertext, 
	    const size_t ciphertextlen,
	    unsigned char** plaintext, 
	    size_t* plaintextlen)
{
  PKCS11_KEY *key;
  EVP_PKEY *pubkey = NULL;
  unsigned char *decrypted = NULL;
  int dec_len;
  int ret, rc;

  if(!tok->cert) {
    _WARN("no certificate selected\n");
    ret = CKI_ERR_CERT; goto decrypt_error;
  }

  // find the key that corresponds to the requested certificate
  key = PKCS11_find_key(tok->cert);
  if (!key) {
    _WARN("no key matching certificate available\n");
    ret = CKI_ERR_KEY; goto decrypt_error;
  }

  // get RSA key
  pubkey = X509_get_pubkey(tok->cert->x509);
  if (pubkey == NULL) {
    _WARN("could not extract public key\n");
    ret = CKI_ERR_KEY; goto decrypt_error;
  }

  dec_len = RSA_size(pubkey->pkey.rsa);
  decrypted = malloc(dec_len);
  if (decrypted == NULL) {
    _ERROR("No memory left\n");
    ret = CKI_ERR_MEM; goto decrypt_error;
  }

  // decrypt data  
  rc = PKCS11_private_decrypt(ciphertextlen, ciphertext, decrypted, key, RSA_PKCS1_PADDING);
  if (rc < 0) {
    _WARN("could not decrypt data\n");
    ret = CKI_ERR_UNKNOWN; goto decrypt_freemem;
  }

  *plaintext = decrypted;
  *plaintextlen = dec_len;
  return CKI_RET_OK;

 decrypt_freemem:
  free(decrypted);
 decrypt_error:
  return ret;
}


int
cki_sign(ckitoken* tok,
	 const unsigned char* message, 
	 const size_t messagelen,
	 unsigned char** signature,
	 size_t* signaturelen)
{
  int ret = 0, rc = 0;
  PKCS11_KEY *key;
  size_t sig_len = 0;
  unsigned char *sig = NULL;

  if(!tok->cert) {
    _WARN("no certificate selected\n");
    return CKI_ERR_CERT;
  }

  // find the key that corresponds to the requested certificate
  key = PKCS11_find_key(tok->cert);
  if (!key) {
    _WARN("no key matching certificate available\n");
    return CKI_ERR_KEY;
  }

  sig_len = SIGLEN;
  sig = malloc(SIGLEN);
  if(!sig) {
    _ERROR("no memory left");
    return CKI_ERR_MEM;
  }

  rc = PKCS11_sign(NID_sha1, message, messagelen, sig, &sig_len, key);
  if(rc != 1) {
    _ERROR("signature failed");
    ret = CKI_ERR_UNKNOWN; goto sign_free;
  }

  *signaturelen = sig_len;
  *signature = sig;

  return ret;

 sign_free:  
  free(signature);

  return ret;
}

int
cki_verify(ckitoken* tok,
	   unsigned char* message, 
	   size_t messagelen,
	   unsigned char* signature,
	   size_t signaturelen)
{
  int ret = 0, rc;
  EVP_PKEY *pubkey = NULL;

  _DEBUG("Verifying signature...\n");

  if(!tok || !tok->cert) {
    _ERROR("could not get certificate\n");
    ret = CKI_ERR_CERT; goto verify_failed;
  }

  pubkey = X509_get_pubkey(tok->cert->x509);
  if (pubkey == NULL) {
    _ERROR("could not extract public key\n");
    ret = CKI_ERR_KEY; goto verify_failed;
  }

  rc = RSA_verify(NID_sha1, message, messagelen,
		  signature, signaturelen, pubkey->pkey.rsa);
  if (rc != 1)
    ret = 1; // failure
  else 
    ret = 0; // success

 verify_failed:
  if (pubkey != NULL)
    EVP_PKEY_free(pubkey);

  return ret;
}


int
do_encrypt(ckitoken *tok, const char* cert_label)
{
  int rc = 0, ret = 0;
  unsigned char *ciphertext = NULL;
  unsigned char *plaintext = NULL;
  size_t ciphertext_len = 0;
  size_t plaintext_len = 0;

  if(!cert_label) {
    _WARN("Cert label requested\n");
    return CKI_ERR_MISSPARAM;
  }

  rc = cki_selectcert(tok, cert_label);
  if(rc) {
    _WARN("No certificate found with label %s\n", cert_label);
    return CKI_ERR_MISSPARAM;
  }

  plaintext = malloc(MAX_TEXT_LEN);
  if(plaintext == NULL) {
    _ERROR("Could not allocate memory for plaintext\n");
    return CKI_ERR_MEM;
  }

  plaintext_len = read_data(stdin, plaintext);
  if(plaintext_len < 0) {
    _ERROR("Could not read plaintext\n");
    ret = CKI_ERR_IO; goto doenc_freeplaintext;
  }

  rc = cki_encrypt(tok, plaintext, plaintext_len, &ciphertext, &ciphertext_len);
  if(rc) {
    _WARN("Encryption failed...\n");
    ERR_print_errors_fp(stderr);
    ret = rc; goto doenc_freeciphertext;
  }

  (void)fwrite(ciphertext, ciphertext_len, 1, stdout);

  ret = 0;

 doenc_freeciphertext:
  if (ciphertext != NULL) {
    memset(ciphertext, 0, ciphertext_len);
    free(plaintext);
  }

 doenc_freeplaintext:
  free(ciphertext);

  return ret;
}

int
do_decrypt(ckitoken *tok, const char* cert_label)
{
  int rc = 0, ret = 0;
  unsigned char *ciphertext = NULL;
  unsigned char *plaintext = NULL;
  size_t ciphertext_len = 0;
  size_t plaintext_len = 0;

  // TODO : check user is authenticated

  if(!cert_label) {
    _WARN("Cert label requested\n");
    return CKI_ERR_MISSPARAM;
  }

  rc = cki_selectcert(tok, cert_label);
  if(rc) {
    _WARN("No certificate found with label %s\n", cert_label);
    return rc;
  }

  ciphertext = malloc(MAX_TEXT_LEN);
  if(ciphertext == NULL) {
    _ERROR("Could not allocate memory for ciphertext\n");
    return CKI_ERR_MEM;
  }

  ciphertext_len = read_data(stdin, ciphertext);
  if(ciphertext_len < 0) {
    _ERROR("Could not read ciphertext\n");
    ret = CKI_ERR_IO; goto dodec_freeciphertext;
  }

  _DEBUG("Decrypting data...\n");

  rc = cki_decrypt(tok, ciphertext, ciphertext_len, &plaintext, &plaintext_len);
  if(rc) {
    _WARN("Decryption failed...\n");
    ERR_print_errors_fp(stderr);
    ret = rc; goto dodec_freeplaintext;
  }

  (void)fwrite(plaintext, plaintext_len, 1, stdout);

  ret = 0;

 dodec_freeplaintext:
  if (plaintext != NULL) {
    memset(plaintext, 0, plaintext_len);
    free(plaintext);
  }

 dodec_freeciphertext:
  free(ciphertext);

  return ret;
}


int 
do_sign(ckitoken *tok, const char* cert_label)
{
  int ret = 0, rc = 0;
  unsigned char *signature = NULL;
  size_t signature_len = 0;
  unsigned char *message = NULL;
  size_t message_len = 0;

  if(!cert_label) {
    _WARN("Cert label required\n");
    return CKI_ERR_MISSPARAM;
  }

  rc = cki_selectcert(tok, cert_label);
  if(rc) {
    _WARN("No certificate found with label %s\n", cert_label);
    return CKI_ERR_MISSPARAM;
  }

  message = malloc(MAX_TEXT_LEN);
  if(message == NULL) {
    _ERROR("Could not allocate memory for message\n");
    return CKI_ERR_MEM;
  }

  message_len = read_data(stdin, message);
  if(message_len < 0) {
    _ERROR("Could not read message\n");
    ret = CKI_ERR_IO; goto dosign_freemess;
  }

  rc = cki_sign(tok, message, message_len, &signature, &signature_len);
  if(rc) {
    _WARN("Signature failed...\n");
    ERR_print_errors_fp(stderr);
    ret = rc; goto dosign_freesig;
  }

  (void)fwrite(signature, signature_len, 1, stdout);

  ret = 0;

 dosign_freesig:
  if(signature != NULL)
    free(signature);
 dosign_freemess:
  free(message);

  return ret;
}

int
do_verify(ckitoken* tok,
	  const char* message_filename,
	  const char* sig_filename,
	  const char* cert_label)
{
  int ret = 0, rc = 0;
  //  int fd_message, fd_signature;
  FILE *fd_message, *fd_signature;
  size_t messagelen, siglen;
  unsigned char* message;
  unsigned char* signature;

  if(!cert_label) {
    _WARN("Cert label required\n");
    return CKI_ERR_MISSPARAM;
  }

  rc = cki_selectcert(tok, cert_label);
  if(rc) {
    _WARN("No certificate found with label %s\n", cert_label);
    return CKI_ERR_MISSPARAM;
  }

  //  fd_message = open(message_filename, O_RDONLY);
  fd_message = fopen(message_filename, "r");
  if(fd_message < 0) {
    _ERROR("Could not read message\n");
    return CKI_ERR_IO;
  }

  message = malloc(MAX_TEXT_LEN);
  if(message == NULL) {
    _ERROR("Could not allocate memory for message\n");
    ret = CKI_ERR_MEM; goto doverif_closemess;
  }

  messagelen = read_data(fd_message, message);
  //  rc = _read(fd_message, message, MAX_TEXT_LEN);
  if(rc) {
    _ERROR("Could not read message\n");
    ret = CKI_ERR_IO; goto doverif_freemess;
  }

  //  fd_signature = open(sig_filename, O_RDONLY);
  fd_signature = fopen(sig_filename, "r");
  if(fd_signature < 0) {
    _ERROR("Could not read signature\n");
    ret = CKI_ERR_IO; goto doverif_freemess;
  }

  signature = malloc(MAX_SIG_LEN);
  if(message == NULL) {
    _ERROR("Could not allocate memory for message\n");
    ret = CKI_ERR_MEM; goto doverif_closesig;
  }

  siglen = read_data(fd_signature, signature);
  //  rc = _read(fd_signature, signature, MAX_SIG_LEN);
  if(rc) {
    _ERROR("Could not read signature\n");
    ret = CKI_ERR_IO; goto doverif_freesig;
  }

  rc = cki_verify(tok, message, messagelen, signature, siglen);
  if(rc == 0) {
    printf("Verification successful\n");
    ret = 0;
  } else if(rc == 1) {
    printf("Verification failed\n");
    ret = 0;
  } else {
    _ERROR("Error while checking signature\n");
    ret = CKI_ERR_UNKNOWN;
  }

 doverif_freesig:
  free(signature);

 doverif_closesig:
  fclose(fd_signature);
  //close(fd_signature);

 doverif_freemess:
  free(message);

 doverif_closemess:
  fclose(fd_message);
  //close(fd_message);

  return ret;
}
