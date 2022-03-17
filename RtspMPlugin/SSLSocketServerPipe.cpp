// see
// https://stackoverflow.com/questions/31171396/openssl-non-blocking-socket-ssl-read-unpredictable
// https://www.openssl.org/docs/man1.1.1/man3/SSL_get_fd.html

#include "SSLSocketServerPipe.h"
#include "GroupsockHelper.hh"
#include "UsageEnvironment.hh"
#include "SocketCommunication.h"

#if defined(__WIN32__) || defined(_WIN32)
#else
  #define INVALID_SOCKET -1
#endif


SSLSocketServerPipe::SSLSocketServerPipe(UsageEnvironment& env) : SSLSocketPipeBase(env)
{
}

SSLSocketServerPipe::~SSLSocketServerPipe()
{
}

bool SSLSocketServerPipe::AcceptClientAndConnectPipe(int socket, unsigned short port, const char* certpath /*= "cert.pem"*/, const char* keypath /*= "key.pem"*/)
{
  do
  {
    m_ctx = createSSLContextServer(certpath,keypath);
    if (!m_ctx) {
m_env << "SSLSocketServerPipe(" << this << ")::AcceptClientAndConnectPipe(" << socket << "," << port << "): "
             "createSSLContextServer failed\n";
      break;
    }
            
    m_sslSocket = socket;
    m_ssl = createSSL(m_sslSocket, m_ctx);
    if (!m_ssl) {
m_env << "SSLSocketServerPipe(" << this << ")::AcceptClientAndConnectPipe(" << socket << "," << port << "): "
             "createSSL failed\n";
      break;
    }

    SSL_set_accept_state(m_ssl);

    //do
    int ret = 0 , ret1 = 0;
    if ((ret = SSL_accept(m_ssl)) <= 0)
    {
      ret1 = SSL_get_error(m_ssl, ret);
      if ( ret1 != SSL_ERROR_WANT_READ ) {
m_env << "SSLSocketServerPipe(" << this << ")::AcceptClientAndConnectPipe(" << socket << "," << port << "): "
             "SSL_accept failed\n";
        return false;
      }
    }

    // Connect to local server port 80
    m_pipeSocket = createClientSocket(/*localhost 127.0.0.1*/ 16777343, port);

    if (m_pipeSocket == INVALID_SOCKET) {
m_env << "SSLSocketServerPipe(" << this << ")::AcceptClientAndConnectPipe(" << socket << "," << port << "): "
             "createClientSocket failed\n";
      break;
    }
m_env << "SSLSocketServerPipe(" << this << ")::AcceptClientAndConnectPipe(" << socket << "," << port << "): "
             "SSL_accept ok, createClientSocket returned " << m_pipeSocket << "\n";

    setBackgroundHandling();
    setInOutSocketBufferSize(1024 * 1024);

    return true;
  } while (false);

  DisconnectPipe();
  return false;
}

void SSLSocketServerPipe::DisconnectPipe()
{
  closeSocketsAndDisableBackgroundHandling();
  cleanup();

  // Delete ourserlves
  delete this;
}

