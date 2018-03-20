//------------------------------------------------------------------------------
// Copyright (c) 2011-2012 by European Organization for Nuclear Research (CERN)
// Author: Michal Simon <simonm@cern.ch>
//------------------------------------------------------------------------------
// XRootD is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// XRootD is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with XRootD.  If not, see <http://www.gnu.org/licenses/>.
//------------------------------------------------------------------------------

#include "XrdTls/XrdTlsCtx.hh"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace XrdTls
{
  Context::Context()
  {
    /* SSL library initialisation */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* create the SSL server context */
    ctx = SSL_CTX_new( SSLv23_method() );
    if( !ctx )
      throw make_tlserr( Exception::ALLOC_ERR );

//        /* Load certificate and private key files, and check consistency */
//        if( SSL_CTX_use_certificate_file( ctx, certfile.c_str(),  SSL_FILETYPE_PEM ) != 1 )
//          throw make_tlserr( TlsErr::CERT_ERR );
//
//        if (SSL_CTX_use_PrivateKey_file( ctx, keyfile.c_str(), SSL_FILETYPE_PEM ) != 1 )
//          throw make_tlserr( TlsErr::KEY_ERR );
//
//        /* Make sure the key and certificate file match. */
//        if( SSL_CTX_check_private_key( ctx ) != 1 )
//          throw make_tlserr( TlsErr::MISMATCH_ERR );
//
//        /* TODO log: "certificate and private key loaded and verified\n" */
//        std::cerr << "certificate and private key loaded and verified" << std::endl;

    /* Recommended to avoid SSLv2 & SSLv3 */
    SSL_CTX_set_options( ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 );

    /* Handle session re-negotiation automatically*/
    SSL_CTX_set_mode( ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_ENABLE_PARTIAL_WRITE );
  }

  Context::~Context()
  {
    SSL_CTX_free( ctx );
  }

  Context::operator SSL_CTX*()
  {
    return ctx;
  }
}
