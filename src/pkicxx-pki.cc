#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include "pkicxx-pki.hpp"
#include "pkicxx-pkic.hpp"

namespace pkicxx{
  pki::pki(){}
  
  pki::~pki()
  {
    
  }
  
  std::vector<unsigned char> pki::encrypt(pkic& key,std::vector<unsigned char>& payload)
  {   
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key.key_container,NULL);
    if(!ctx) return {};

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }
    size_t len;
    if (EVP_PKEY_encrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }
    std::vector<unsigned char> encrypted(len);
    if(EVP_PKEY_encrypt(ctx,encrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
  }

  void pki::decrypt()
  {
    
  }

  void pki::sign()
  {
    
  }
}
