#pragma once
#include "SSLSocketBase.h"


class SSLSocketServerPipe : public SSLSocketPipeBase
{
public:
  SSLSocketServerPipe(UsageEnvironment& env);
  virtual  ~SSLSocketServerPipe();

    // Connects to server and opens connections ( waiting for reply ).
    virtual bool  AcceptClientAndConnectPipe( int socket, unsigned short port, const char* certpath = "cert.pem", const char* keypath = "key.pem");
    virtual void  DisconnectPipe();
};

