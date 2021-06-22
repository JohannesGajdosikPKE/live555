#pragma once

#include <thread>
#include <mutex>
#include <condition_variable>

typedef void ConnectionReadyFunc(void* clientData, int sock);

class ConnectionPipe
{
  ConnectionPipe();
  ~ConnectionPipe() {  CloseThread(); };
  
public:
  static ConnectionPipe& Instance()
  {
    static ConnectionPipe instance;
    return instance;
  };
  void ListenToLocalConnection(ConnectionReadyFunc * func, void * clientData);

protected:
  void CloseThread();

private:
  static void ThreadFunc(void* data)
  {
    if (data)
      ((ConnectionPipe*)data)->ThreadFunc1();
  };

  void ThreadFunc1();

private:
  SOCKET serverSocket;
  ConnectionReadyFunc* m_callbackFunc;
  void*                m_callBackData;
  bool                    m_threadRunning;
  std::mutex              m_lock;
  std::thread*            m_thread;
  std::condition_variable m_threadReady;
  std::condition_variable m_threadListen;
  std::condition_variable m_threadFinished;
};

extern int sockPipePort;

bool createSocketPipe(SOCKET &receiver, SOCKET &sender, int serverPort = 0);
int  getSocketPipeDefaultPort();
