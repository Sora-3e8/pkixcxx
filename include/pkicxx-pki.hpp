#ifndef PKICXX_PKI_HPP
#define PKICXX_PKI_HPP

#include <string>
#include <vector>

extern "C" struct evp_pkey_st;

namespace pkicxx
{
  class pkic;
  class pki
  {
    public:
      pki();
      ~pki();
      std::vector<unsigned char> encrypt(pkic& key,std::vector<unsigned char>& payload);
      void decrypt();
      void sign();
  };
}
#endif
