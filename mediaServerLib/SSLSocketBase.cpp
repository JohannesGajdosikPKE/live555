// see
// https://stackoverflow.com/questions/64503074/when-am-trying-to-do-ssl-connect-return-0-and-ssl-get-error-return-5

#include "SSLSocketBase.h"
#include "UsageEnvironment.hh"
#include "GroupsockHelper.hh"
#include "openssl\ssl.h"

#include <iostream>

static bool g_SSL_initialized = false;

void initialize()
{

  if (g_SSL_initialized)
    return;

  /* ---------------------------------------------------------- *
  * These function calls initialize openssl for correct work.  *
  * ---------------------------------------------------------- */

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  /* ---------------------------------------------------------- *
  * initialize SSL library and register algorithms             *
  * ---------------------------------------------------------- */
  if (SSL_library_init() < 0)
  {
    return;
  }

  g_SSL_initialized = true;
  return;
}

void deinitialize()
{
  ERR_free_strings();
  EVP_cleanup();
}

std::ostream& operator<<(std::ostream& os, const SSLSocketBase& source)
{
  os << "SSLSocketBase [" << &source << "]: ";
  return os;
}

const char* SSLSocketBase::getError(SSL* ssl)
{
  return ERR_error_string(SSL_get_verify_result(ssl), NULL);
}

const char* SSLSocketBase::getCertError(SSL* ssl)
{
  return X509_verify_cert_error_string(SSL_get_verify_result(ssl));
}

SSL_CTX* SSLSocketBase::createSSLContextClient( long options )
{
  if (!g_SSL_initialized)
    return NULL;

  // Negotiate highest available SSL / TLS version
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());

  if (ctx)
  {
    // options allow TLS 1.1 and above as default, but can be changed thru registry
    SSL_CTX_set_options(ctx, options);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

  }

  return ctx;
}

SSL_CTX* SSLSocketBase::createSSLContextServer(const char* certpath, const char* keypath)
{
  if (!g_SSL_initialized)
    return NULL;

  // Negotiate highest available SSL / TLS version
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());

  if (ctx)
  {
    // Leave TLSv1_1 and above for negotiation (as a server, we don't offer deprecated versions at all)
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_ALL);

    // Context configuration
    SSL_CTX_set_ecdh_auto(ctx, 1);

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    
    do
    {

      /* Set the key and cert */
      if (SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM) <= 0) {
        std::cout << "Unable to read certificate file." << certpath << std::endl;
        break;
      }

      if (SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM) <= 0) {
        std::cout << "Unable to read certificate key." << keypath << std::endl;
        break;
      }

      return ctx;
    } while (false);

    SSL_CTX_free(ctx);
    ctx = NULL;
  }

  return ctx;
}

SSL* SSLSocketBase::createSSL(int socket, SSL_CTX* context)
{
  if (!g_SSL_initialized)
    return NULL;

  SSL* ssl = SSL_new(context);
  SSL_set_fd(ssl, socket);

  return ssl;
}

bool SSLSocketBase::checkSSLCertificate(SSL* ssl)
{
  if (ssl == NULL)
    return false;

  /* Get server's certificate (note: beware of dynamic allocation) - opt */
  std::string temp2 = X509_verify_cert_error_string(SSL_get_verify_result(ssl));

  X509* cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    return false;

  do
  {
    char* str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    if (str == NULL)
      break;

    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    if (str == NULL)
      break;

    OPENSSL_free(str);

    /* We could do all sorts of certificate verification stuff here before
    deallocating the certificate. */

    return true;
  } while (false);

  if (cert)
    X509_free(cert);

  return false;
}

SSLSocketPipeBase::SSLSocketPipeBase(UsageEnvironment& env) 
  : SSLSocketBase(env),
  m_ssl(NULL),
  m_ctx(NULL),
  m_pipeSocket(INVALID_SOCKET),
  m_sslSocket(INVALID_SOCKET),
  fWritingBytesLeft(0),
  fWritingBufferOffset(0)
{

}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
int SSLSocketPipeBase::createClientSocket(unsigned long serverIp, unsigned short port)
{
  int sockfd = INVALID_SOCKET;
  char      *tmp_ptr = NULL;
  struct sockaddr_in dest_addr;

  // create the basic TCP socket                                
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = serverIp;

  // Zeroing the rest of the struct                            
  memset(&(dest_addr.sin_zero), '\0', 8);
  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  // Try to make the host connect here                          
  if (connect(sockfd, (struct sockaddr *) &dest_addr,
    sizeof(struct sockaddr)) == -1) {
    //    std::cout << "Error: Cannot connect to host " << serverIp << ":" << port << std::endl;
    return INVALID_SOCKET;
  }

  return sockfd;
}

static char *ossl_strerror(unsigned long error, char *buf, size_t size)
{
  ERR_error_string_n(error, buf, size);
  return buf;
}

static const char *SSL_ERROR_to_str(int err)
{
  switch (err) {
  case SSL_ERROR_NONE:
    return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:
    return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:
    return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:
    return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:
    return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:
    return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:
    return "SSL_ERROR_WANT_ACCEPT";
#if defined(SSL_ERROR_WANT_ASYNC)
  case SSL_ERROR_WANT_ASYNC:
    return "SSL_ERROR_WANT_ASYNC";
#endif
#if defined(SSL_ERROR_WANT_ASYNC_JOB)
  case SSL_ERROR_WANT_ASYNC_JOB:
    return "SSL_ERROR_WANT_ASYNC_JOB";
#endif
#if defined(SSL_ERROR_WANT_EARLY)
  case SSL_ERROR_WANT_EARLY:
    return "SSL_ERROR_WANT_EARLY";
#endif
  default:
    return "SSL_ERROR unknown";

  }
}

int SSLSocketPipeBase::handleSSLRead(const unsigned char* buffer, const unsigned int bufferSize)
{
  struct sockaddr_in dummy; // 'from' address, meaningless in this case
                            // Read the data from SSL Socket and write it to the socket pipe
  int ssl_error = 0;
  int bytesWritten = 0;

  bool finished_reading = false;
  int offset = 0;
  int bytesRead = 0;
  int done = 0;
  char buf[256];

  ERR_clear_error();
  int pendin_data = 0;

  /* Something to read, let's do it and hope that it is the close
    notify alert from the server */
  int nread = SSL_read(m_ssl, (void*)(buffer + bytesRead), bufferSize - bytesRead);

  if (nread <= 0) {
    /* failed SSL_read */
    int err = SSL_get_error(m_ssl, (int)nread);

    switch (err) {
    case SSL_ERROR_NONE: /* this is not an error */
    case SSL_ERROR_ZERO_RETURN: /* no more data */
      return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there's data pending, re-invoke SSL_read() */
//      std::cout << " ssl-> reading data " << SSL_ERROR_to_str(err) << std::endl;
      return 0;
    case SSL_ERROR_SYSCALL:
//      std::cout << " ssl-> reading data failed! -> socket disconnected! " << SSL_ERROR_to_str(err) << std::endl;
      return -1;
    default:
      /* openssl/ssl.h for SSL_ERROR_SYSCALL says "look at error stack/return
      value/errno" */
      /* https://www.openssl.org/docs/crypto/ERR_get_error.html */
      auto sslerror = ERR_get_error();

      if ((nread < 0) || sslerror) {
        /* If the return code was negative or there actually is an error in the
        queue */
//        std::cout << " ssl-> reading data failed! " << SSL_ERROR_to_str(err) << std::endl;
        return -1;
      }

    }
  }

  return nread;
}

int SSLSocketPipeBase::handleSSLWrite(const unsigned char* buffer, const unsigned int bufferSize)
{
  int offset = 0;
  int ret = 0;
  int written = 0;
  char buf[256];

  ERR_clear_error();
  int err = 0;


  // try to write to the ssl socket, if this is not possible 
  // wait and try again later
  int rc = SSL_write(m_ssl, buffer, bufferSize);

  if (rc <= 0) {
    err = SSL_get_error(m_ssl, rc);

    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    {
      /* The operation did not complete; the same TLS/SSL I/O function
      should be called again later. This is basically an EWOULDBLOCK
      equivalent. */
      std::cout << " ->ssl writing  " << SSL_ERROR_to_str(err) << std::endl;
      return 0;
    }
    case SSL_ERROR_SYSCALL: 
      std::cout << " ->ssl writing data failed! socket disconnected! " << SSL_ERROR_to_str(err) << std::endl;
      return -1;

    case SSL_ERROR_SSL:
      std::cout << " ->ssl writing data failed! " << SSL_ERROR_to_str(err) << std::endl;
      return -1;
    }
    return -1;
  }

  return rc;
}


void SSLSocketPipeBase::setBackgroundHandling()
{
  // Add the background handling for the socket pipe and ssl socket
  makeSocketNonBlocking(m_pipeSocket);
  m_env.taskScheduler().setBackgroundHandling(m_pipeSocket, SOCKET_READABLE | SOCKET_EXCEPTION, handlePipeInData, this);

  makeSocketNonBlocking(m_sslSocket);
  m_env.taskScheduler().setBackgroundHandling(m_sslSocket, SOCKET_READABLE | SOCKET_EXCEPTION, handleSSLSocketData, this);
}

void SSLSocketPipeBase::setInOutSocketBufferSize(const unsigned int newsize)
{
  setSendBufferTo(m_env, m_pipeSocket, newsize);
  setSendBufferTo(m_env, m_sslSocket, newsize);

  setReceiveBufferTo(m_env, m_pipeSocket, newsize);
  setReceiveBufferTo(m_env, m_sslSocket, newsize);
}

void SSLSocketPipeBase::closeSocketsAndDisableBackgroundHandling()
{
  // Close pipe
  if (m_pipeSocket != INVALID_SOCKET)
  {
    m_env.taskScheduler().disableBackgroundHandling(m_pipeSocket);
    closesocket(m_pipeSocket);
    m_pipeSocket = INVALID_SOCKET;
  }

  if (m_sslSocket != INVALID_SOCKET)
  {
    m_env.taskScheduler().disableBackgroundHandling(m_sslSocket);
    closesocket(m_sslSocket);
    m_sslSocket = INVALID_SOCKET;
  }
}

void SSLSocketPipeBase::disablePipeInHandling()
{
  // Close pipe
  if (m_pipeSocket != INVALID_SOCKET)
  {
    m_env.taskScheduler().disableBackgroundHandling(m_pipeSocket);
  }
}

void SSLSocketPipeBase::disableSSLInHandling()
{
  // Close pipe
  if (m_sslSocket != INVALID_SOCKET)
  {
    m_env.taskScheduler().disableBackgroundHandling(m_sslSocket);
  }
}

//////////////////////////////////////////////////////////////////////////
// CallBack handlingset_c
void SSLSocketPipeBase::copyDataToSSLSocket()
{
  // Read the data from socket pipe and write it to ssl socket
  struct sockaddr_storage dummy; // 'from' address, meaningless in this case
  int dataLen = fWritingBufferOffset + fWritingBytesLeft;
  int bytesRead = readSocket(m_env, m_pipeSocket, fWritingBuffer + dataLen, sizeof(fWritingBuffer) - dataLen, dummy);
  if (bytesRead < 0)
  {
    std::cout << " in->ssl: Error reading pipe input!" << std::endl;
    DisconnectPipe();
    return;
  }

  fWritingBytesLeft += bytesRead;

  int bytesWritten = handleSSLWrite(fWritingBuffer + fWritingBufferOffset, fWritingBytesLeft);
  if ( bytesWritten < 0 )
  {
    std::cout << " in->ssl: Error writing to ssl output!" << std::endl;
    DisconnectPipe();
    return;
  }
   
  fWritingBytesLeft -= bytesWritten;
  fWritingBufferOffset += bytesWritten;

  if (fWritingBytesLeft == 0)
    fWritingBufferOffset = 0;

   /* std::string temp2 = getCertError(m_ssl);
 //    std::string temp = getError(m_ssl);*/
//  std::cout << " in->ssl: " << bytesRead << " bytes " /*<< temp + " " + temp2*/ << std::endl;
}

void SSLSocketPipeBase::copyDataToSocketPipe()
{
  struct sockaddr_in dummy; // 'from' address, meaningless in this case
                            // Read the data from SSL Socket and write it to the socket pipe

  int read_blocked, bytesRead, ssl_error;
  do {

    bytesRead = handleSSLRead(fReadingBuffer, sizeof(fReadingBuffer));
    if (bytesRead < 0)
    {
//      std::cout << " ssl->out: Error reading from ssl input." << std::endl;
      DisconnectPipe();
      return;
    }

    //if (bytesRead == 0)
    //  continue;

    int bytesWritten = send(m_pipeSocket, (char*)fReadingBuffer, bytesRead, 0);
    if (bytesWritten < 0)
    {
//      std::cout << " ssl->out: Error writing to pipe output!" << std::endl;
      DisconnectPipe();
      return;
    }

    _ASSERTE(bytesRead == bytesWritten);

  } while (SSL_pending(m_ssl));

//  std::cout << " ssl->out: " << bytesRead << " bytes" << std::endl;
}

void SSLSocketPipeBase::cleanup()
{
  if (m_ssl)
  {
    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
  }
  m_ssl = NULL;

  if (m_ctx)
    SSL_CTX_free(m_ctx);

  m_ctx = NULL;
}
