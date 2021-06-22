#pragma once
#include "UsageEnvironment.hh"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

void initialize();
void deinitialize();


class SSLSocketBase
{
  
protected:

  SSLSocketBase(UsageEnvironment& env) : m_env( env) { initialize(); };
  virtual ~SSLSocketBase() {};

  const char* getError(SSL* ssl);;
  const char* getCertError(SSL* ssl);;

  SSL_CTX* createSSLContextClient(long options);
  SSL_CTX* createSSLContextServer( const char* certpath, const char* keypath );
  SSL*     createSSL(int socket, SSL_CTX* context);
  
  bool checkSSLCertificate(SSL* ssl);

protected:
  UsageEnvironment &m_env;
};

class SSLSocketPipeBase : public SSLSocketBase
{

public:
  SSLSocketPipeBase(UsageEnvironment& env);
  virtual ~SSLSocketPipeBase() { cleanup(); }
  
protected:
  int createClientSocket(unsigned long serverIp, unsigned short port);
  
  int handleSSLRead(const unsigned char* buffer, const unsigned int bufferSize);
  int handleSSLWrite(const unsigned char* buffer, const unsigned int bufferSize);
  
  void setBackgroundHandling();
  void setInOutSocketBufferSize(const unsigned int newsize);
  void closeSocketsAndDisableBackgroundHandling();
  
  void disablePipeInHandling();
  void disableSSLInHandling();
  static void handlePipeInData(void* clientData, int /*mask*/)
  {
    if (clientData != NULL)
      ((SSLSocketPipeBase*)clientData)->copyDataToSSLSocket();
  };

  static void handleSSLSocketData(void* clientData) { handleSSLSocketData(clientData, 0); };
  static void handleSSLSocketData(void* clientData, int /*mask*/)
  {
    if (clientData != NULL)
      ((SSLSocketPipeBase*)clientData)->copyDataToSocketPipe();
  };

  void copyDataToSSLSocket();
  void copyDataToSocketPipe();

  void cleanup();

  virtual void DisconnectPipe() = 0;
protected:
  SSL*     m_ssl;
  SSL_CTX* m_ctx;

  int m_sslSocket;
  int m_pipeSocket;

#define BUFFER_SIZE 1024*1024
  unsigned char fWritingBuffer[BUFFER_SIZE];
  unsigned char fReadingBuffer[BUFFER_SIZE];

  unsigned int fWritingBytesLeft;
  unsigned int fWritingBufferOffset;

};
