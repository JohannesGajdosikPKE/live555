// See
// https://stackoverflow.com/questions/23394188/writing-client-and-server-udp
// https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket

#include "SocketCommunication.h"
#include "GroupsockHelper.hh"

#if defined(__WIN32__) || defined(_WIN32)
  #include <winsock2.h>
  extern "C" int initializeWinsockIfNecessary();
#else
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
  #define SOCKET int
  #define SOCKADDR sockaddr
  #define closesocket ::close
  #include <sys/types.h>          /* See NOTES */
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

#include <iostream>

std::mutex g_lock;


int getSocketPipeDefaultPort();

int sockPipePort = getSocketPipeDefaultPort();

int getSocketPipeDefaultPort()
{
  return 17000;
};


bool createSocketPipe(SOCKET &receiver, SOCKET &sender, int serverPort)
{

  // set the port number if needed
  if (serverPort == 0)
  {
    serverPort = sockPipePort;
  }

#if defined(__WIN32__) || defined(_WIN32)
  if (!initializeWinsockIfNecessary())
  {
    std::cout << "createSocketPipe(): Failed to initialize 'winsock' " << std::endl;
    return false;
  }
#endif

  std::lock_guard<std::mutex> lock(g_lock);

  SOCKET serverSocket = INVALID_SOCKET, clientSocket = INVALID_SOCKET, connectedSock = INVALID_SOCKET;
  int rc = SOCKET_ERROR;

  do
  {

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET)
    {
      std::cout << "createSocketPipe(): Unable to initialize socket! " << std::endl;
      break;
    }

#if defined(__WIN32__) || defined(_WIN32)
    // Set the exclusive address option
    int iOptval = 1;
    int iResult = setsockopt(serverSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
      (char *)&iOptval, sizeof(iOptval));
  
    if (iResult == SOCKET_ERROR) 
    {
      std::cout << "createSocketPipe(): Unable to set exclusive property on socket! " << std::endl;
      break;
    }
#endif

    // The socket address to be passed to bind
    sockaddr_in service;

    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");

    static const int portRange = 10;

    // Try all the ports between <serverPort-portRange and serverPort > 
    for (int i = 0; i < portRange; i++)
    {
      unsigned short port = (unsigned short) ((serverPort - i) & 0xffff);
      service.sin_port = htons(port);

      // bind socket to a certain port and address
      rc = ::bind(serverSocket, (SOCKADDR *)&service, sizeof(service));
      if (SOCKET_ERROR != rc)
        break;

      // lets try another port
      std::cout << "createSocketPipe(): port number " << i << " is exclusivelly locked - unable to bind the socket to the port!" << std::endl;
    }

    if (rc == SOCKET_ERROR)
    {
      std::cout << "createSocketPipe(): Unable to bind socket! " << std::endl;
      break;
    }

    rc = listen(serverSocket, 1);
    if (rc == SOCKET_ERROR)
    {
      std::cout << "createSocketPipe(): Unable to listen to socket! " << std::endl;
      break;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
      std::cout << "createSocketPipe(): Unable to create clientSocket! " << std::endl;
      break;
    }

    if (!makeSocketBlocking(clientSocket))
    {
      std::cout << "createSocketPipe(): Unable to set blocking propery on socket! " << std::endl;
      break;
    }


    rc = connect(clientSocket, (SOCKADDR *)&service, sizeof(service));
    if (rc == SOCKET_ERROR)
    {
      std::cout << "createSocketPipe(): Unable to connect to socket! " << std::endl;
      break;
    }

    connectedSock = accept(serverSocket, NULL, NULL);
    if (connectedSock == INVALID_SOCKET)
    {
      std::cout << "createSocketPipe(): Unable to accept the socket connection! " << std::endl;
      break;
    }

     if (!makeSocketNonBlocking(clientSocket))
     {
       std::cout << "createSocketPipe(): Unable to set non-blocking property to socket! " << std::endl;
       break;
     }

    receiver = connectedSock;
    sender = clientSocket;

    if (serverSocket != INVALID_SOCKET)
      closesocket(serverSocket);

    return true;


  } while (false);

  if (serverSocket != INVALID_SOCKET)
    closesocket(serverSocket);

  if (clientSocket != INVALID_SOCKET)
    closesocket(clientSocket);

  if (connectedSock != INVALID_SOCKET)
    closesocket(connectedSock);

  // return sock && csock   sock - recv  csock - send
  return false;

}

//////////////////////////////////////////////////////////////////////////

void ConnectionPipe::ListenToLocalConnection(ConnectionReadyFunc* func, void* clientData)
{
  {
    std::unique_lock<std::mutex> lck(m_lock);
    m_threadFinished.wait(lck, [this] { return !m_threadRunning; });
    
    CloseThread();

    m_callBackData = clientData;
    m_callbackFunc = func;
    m_thread = new std::thread(ThreadFunc, this);

    m_threadReady.wait(lck, [this] { return m_threadRunning; });
    m_threadListen.notify_one();
  }
}

void ConnectionPipe::ThreadFunc1()
{

  std::unique_lock<std::mutex> lck(m_lock);
  SOCKET serverSocket = INVALID_SOCKET;

  do
  {
    m_threadRunning = true;

#if defined(__WIN32__) || defined(_WIN32)
    // serverSocketInitialization
    if (!initializeWinsockIfNecessary())
      break;
#endif

    int rc = SOCKET_ERROR;

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET)
      break;

    // The socket address to be passed to bind
    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
    service.sin_port = htons(sockPipePort);

    // bind socket to a certain port and address
    rc = ::bind(serverSocket, (SOCKADDR *)&service, sizeof(service));
    if (rc == SOCKET_ERROR)
      break;

    rc = listen(serverSocket, 1);
    if (rc == SOCKET_ERROR)
      break;

    if (!makeSocketBlocking(serverSocket))
      break;

  } while (false);
 
  m_threadReady.notify_one();
  m_threadListen.wait(lck);

  if (serverSocket != INVALID_SOCKET)
  {
    fd_set readSet;    FD_ZERO(&readSet);
    FD_SET(serverSocket, &readSet);

    timeval timeout;
    timeout.tv_sec = 1;  // wait for max one second timeout
    timeout.tv_usec = 0;

    if (select(serverSocket, &readSet, NULL, NULL, &timeout) == 1)
    {
      //std::unique_lock<std::mutex> lck(m_lock);
      SOCKET sock = accept(serverSocket, NULL, NULL);
      if (sock != INVALID_SOCKET)
      {
        if (m_callbackFunc != NULL && m_callBackData != NULL)
        {
          m_callbackFunc(m_callBackData, sock);
          m_callBackData = NULL;
          m_callbackFunc = NULL;
          std::cout << "ConnectionPipe(): pipe is beeing accepted!" << std::endl;
        }
        else
          closesocket(sock);
      };
    }
  }

  if (serverSocket != INVALID_SOCKET)
  {
    closesocket(serverSocket);
    serverSocket = INVALID_SOCKET;
  }

  m_threadRunning = false;
  m_threadFinished.notify_one();
}

void ConnectionPipe::CloseThread()
{
  if (m_thread)
  {
    if (m_thread->joinable())
      m_thread->join();

    delete m_thread;
    m_thread = NULL;
  }
}

ConnectionPipe::ConnectionPipe()
  : m_threadRunning(false)
  , m_thread(NULL)
  , m_callbackFunc(NULL)
  , m_callBackData(NULL)
{
}
