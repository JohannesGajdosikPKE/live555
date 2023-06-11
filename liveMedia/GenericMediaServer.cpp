/**********
This library is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the
Free Software Foundation; either version 3 of the License, or (at your
option) any later version. (See <http://www.gnu.org/copyleft/lesser.html>.)

This library is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
more details.

You should have received a copy of the GNU Lesser General Public License
along with this library; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
**********/
// "liveMedia"
// Copyright (c) 1996-2022 Live Networks, Inc.  All rights reserved.
// A generic media server class, used to implement a RTSP server, and any other server that uses
//  "ServerMediaSession" objects to describe media to be served.
// Implementation

#include "GenericMediaServer.hh"
#include <GroupsockHelper.hh>
#include <BasicUsageEnvironment.hh>

#include <thread>
#include <vector>
#include <iostream>

#if defined(__WIN32__) || defined(_WIN32) || defined(_QNX4)
#define snprintf _snprintf
#endif

////////// GenericMediaServer implementation //////////

void GenericMediaServer::addServerMediaSession(const std::shared_ptr<ServerMediaSession> &serverMediaSession) {
  if (!serverMediaSession) return;
  
  char const* sessionName = serverMediaSession->streamName();
  if (sessionName == NULL) sessionName = "";
  {
    std::lock_guard<std::recursive_mutex> guard(sms_mutex);
    fServerMediaSessions[&serverMediaSession->envir()][sessionName] = serverMediaSession;
  }
}

void GenericMediaServer
::lookupServerMediaSession(UsageEnvironment& env, char const* streamName,
			   lookupServerMediaSessionCompletionFunc* completionFunc,
			   void* completionClientData,
			   Boolean /*isFirstLookupInSession*/) {
  // Default implementation: Do a synchronous lookup, and call the completion function:
  if (completionFunc != NULL) {
    std::lock_guard<std::recursive_mutex> guard(sms_mutex);
    (*completionFunc)(completionClientData, getServerMediaSession(env,streamName));
  }
}

struct lsmsMemberFunctionRecord {
  GenericMediaServer* fServer;
  void (GenericMediaServer::*fMemberFunc)(const std::shared_ptr<ServerMediaSession> &);
};

static void lsmsMemberFunctionCompletionFunc(void* clientData, const std::shared_ptr<ServerMediaSession> &sessionLookedUp) {
  lsmsMemberFunctionRecord* memberFunctionRecord = (lsmsMemberFunctionRecord*)clientData;
  (memberFunctionRecord->fServer->*(memberFunctionRecord->fMemberFunc))(sessionLookedUp);
  delete memberFunctionRecord;
}

void GenericMediaServer
::lookupServerMediaSession(UsageEnvironment& env, char const* streamName,
			   void (GenericMediaServer::*memberFunc)(const std::shared_ptr<ServerMediaSession> &)) {
  struct lsmsMemberFunctionRecord* memberFunctionRecord = new struct lsmsMemberFunctionRecord;
  memberFunctionRecord->fServer = this;
  memberFunctionRecord->fMemberFunc = memberFunc;
  
  GenericMediaServer
    ::lookupServerMediaSession(env, streamName,
			       lsmsMemberFunctionCompletionFunc, memberFunctionRecord);
}

void GenericMediaServer::removeServerMediaSession(const ServerMediaSession &serverMediaSession) {
//  envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ") start\n";
  std::lock_guard<std::recursive_mutex> lock(sms_mutex);
  const unsigned int count = fServerMediaSessions[&(serverMediaSession.envir())].erase(serverMediaSession.streamName());
//  envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ") end\n";
}

#ifdef NOT_NEEDED
void GenericMediaServer::removeServerMediaSession(UsageEnvironment &env, char const* streamName) {
//  env << "GenericMediaServer::removeServerMediaSession(" << streamName << ") start\n";
  lookupServerMediaSession(env, streamName, &GenericMediaServer::removeServerMediaSession);
//  env << "GenericMediaServer::removeServerMediaSession(" << streamName << ") end\n";
}
#endif

void GenericMediaServer::closeAllClientSessionsForServerMediaSession(const ServerMediaSession &serverMediaSession) {

  Semaphore sem;
  unsigned int post_count = 0;
  {
    std::vector<std::shared_ptr<ClientSession> > sessions_of_this_thread;
      // declare guard *after* sessions_of_this_thread:
    std::lock_guard<std::recursive_mutex> guard(fClientSessions_mutex);
    for (auto iter(fClientSessions.begin());iter!=fClientSessions.end();) {
        // the RTSPClientSession destructor delets the "streamStates" which in turn delete....
        // So I cannot delete it in aother thread
      if (iter->second->getOurServerMediaSession().get() == &serverMediaSession) {
        TaskScheduler &scheduler(iter->second->envir().taskScheduler());
        if (scheduler.isSameThread()) {
          sessions_of_this_thread.push_back(std::move(iter->second));
        } else {
          scheduler.executeCommand([clientSession=std::move(iter->second),&sem](uint64_t) mutable {
              // deleting clientSession in proper thread because
              // ~RTSPClientSession deletes the StreamStates which deletes the ServerMediaSession
            clientSession.reset();
              // I cannot guarantee that all clientSessions are deleted when this function finishes
            sem.post();
          });
          post_count++;
        }
        fClientSessions.erase(iter++);
      } else {
        ++iter;
      }
    }
      // guard is released, then sessions_of_this_thread is released
  }
  while (post_count) {
    sem.wait();
    post_count--;
  }
}

#ifdef NOT_NEEDED
void GenericMediaServer::closeAllClientSessionsForServerMediaSession(char const* streamName) {
  lookupServerMediaSession(envir(), streamName,
			   &GenericMediaServer::closeAllClientSessionsForServerMediaSession);
}
#endif

void GenericMediaServer::deleteServerMediaSession(const std::shared_ptr<ServerMediaSession> &serverMediaSession) {
  closeAllClientSessionsForServerMediaSession(*serverMediaSession);
  removeServerMediaSession(*serverMediaSession);
}

#ifdef NOT_NEEDED
void GenericMediaServer::deleteServerMediaSession(UsageEnvironment &env, char const* streamName) {
  env << "GenericMediaServer::deleteServerMediaSession(" << streamName << ") start\n";
  lookupServerMediaSession(env, streamName, &GenericMediaServer::deleteServerMediaSession);
  env << "GenericMediaServer::deleteServerMediaSession(" << streamName << ") end\n";
}
#endif

void GenericMediaServer::deleteAllServerMediaSessions(char const* streamName) {
      // delete seesions with this name from all UsageEnvironments
  envir() << "GenericMediaServer::deleteAllServerMediaSessions(" << streamName << ") start\n";
  std::vector<std::shared_ptr<ServerMediaSession> > tmp;
  {
    std::lock_guard<std::recursive_mutex> guard(sms_mutex);
    for (auto &m : fServerMediaSessions) {
      auto it = m.second.find(streamName);
      if (it != m.second.end()) {
        auto s = it->second.lock();
        m.second.erase(it);
        if (s) tmp.push_back(s);
      }
    }
  }
  for (auto &it : tmp) closeAllClientSessionsForServerMediaSession(*it);
  envir() << "GenericMediaServer::deleteAllServerMediaSessions(" << streamName << ") end\n";
}

class GenericMediaServer::Worker {
public:
  Worker(GenericMediaServer &server)
    : worker_thread([this,&server](void) {
//        std::cout << "GenericMediaServer::Worker::mainThread(" << std::this_thread::get_id() << "): start" << std::endl << std::flush;
        scheduler = BasicTaskScheduler::createNew();
        scheduler->assert_threads = true;
//        std::cout << "GenericMediaServer::Worker::mainThread(" << std::this_thread::get_id() << "): scheduler created" << std::endl << std::flush;
        env = server.createNewUsageEnvironment(*scheduler);
        watchVariable = 0;
        sem.post();
        (*env) << "GenericMediaServer::Worker::mainThread: start\n";
        env->taskScheduler().doEventLoop(&watchVariable);
        (*env) << "GenericMediaServer::Worker::mainThread: end\n";
        sem.post();
        sem2.wait();
      }) {
    sem.wait();
  }
  ~Worker(void) {
    if (!env->reclaim()) {
      *env << "GenericMediaServer::Worker::mainThread: env->reclaim failed"
              " and destruction in live555 is a mess. Prefer memleak over crash/abort\n";
    }
    env = nullptr;
    delete scheduler; scheduler = nullptr;
  }
  void joinThread(void) {
    try {
      worker_thread.join();
    } catch (std::system_error &e) {
      fprintf(stderr,"GenericMediaServer::Worker::joinThread: join failed, %s\n",e.what());
      abort();
    }
  }
  void stop(void) {
    scheduler->executeCommand([w=&watchVariable](uint64_t){*w=1;});
  }
  void waitUnitStopped(void) {
    sem.wait();
    sem2.post();
  }
  UsageEnvironment& getEnv(void) const {return *env;}
  int getLoad(void) const {return scheduler->addNrOfUsers(0);}
private:
  BasicTaskScheduler *scheduler = nullptr;
  UsageEnvironment *env = nullptr;
  char volatile watchVariable = 1;
  std::thread worker_thread;
  GenericMediaServer::Semaphore sem,sem2;
};

static inline unsigned int GetNrOfCores(void) {
  unsigned int rval = std::thread::hardware_concurrency();
  if (rval == 0) rval = 32; // C++ does not know the nr of cores
  else if (rval > 1024) rval = 1024; // sanity check
  return rval;
}

GenericMediaServer
::GenericMediaServer(UsageEnvironment& env, int ourSocketIPv4, int ourSocketIPv6, Port ourPort,
                     unsigned reclamationSeconds)
  : Medium(env),
    fServerSocketIPv4(ourSocketIPv4), fServerSocketIPv6(ourSocketIPv6),
    fServerPort(ourPort), fReclamationSeconds(reclamationSeconds),
    fPreviousClientSessionId(0),
    fTLSCertificateFileName(NULL), fTLSPrivateKeyFileName(NULL),
    nr_of_workers(GetNrOfCores()),
    workers(new std::unique_ptr<Worker>[nr_of_workers]),
    cleanup_called(false) {
//fprintf(stderr,"GenericMediaServer::GenericMediaServer: %u workers\n", nr_of_workers);
  ignoreSigPipeOnSocket(fServerSocketIPv4); // so that clients on the same host that are killed don't also kill us
  ignoreSigPipeOnSocket(fServerSocketIPv6); // ditto
  
  // Arrange to handle connections from others:
  env.taskScheduler().turnOnBackgroundReadHandling(fServerSocketIPv4, incomingConnectionHandlerIPv4, this);
  env.taskScheduler().turnOnBackgroundReadHandling(fServerSocketIPv6, incomingConnectionHandlerIPv6, this);
}

GenericMediaServer::~GenericMediaServer() {
  if (!cleanup_called) abort();
  delete[] workers;
  // Turn off background read handling:
  envir().taskScheduler().turnOffBackgroundReadHandling(fServerSocketIPv4);
  ::closeSocket(fServerSocketIPv4);
  envir().taskScheduler().turnOffBackgroundReadHandling(fServerSocketIPv6);
  ::closeSocket(fServerSocketIPv6);

  delete[] fTLSCertificateFileName; delete[] fTLSPrivateKeyFileName;
}

UsageEnvironment *GenericMediaServer::createNewUsageEnvironment(TaskScheduler &scheduler) {
  return BasicUsageEnvironment::createNew(scheduler);
}

UsageEnvironment &GenericMediaServer::getBestThreadedUsageEnvironment(void) {
  std::lock_guard<std::mutex> lock(workers_mutex);
  int best_i = nr_of_workers;
  int best_load = 0x7FFFFFFF;
  for (int i=nr_of_workers-1;i>=0;i--) {
    const int load = workers[i] ? workers[i]->getLoad() : 0;
    if (load < best_load ||
        (load == best_load && (workers[i] || !workers[best_i]))) {
      best_load = load;
      best_i = i;
    }
  }
  if (!workers[best_i]) workers[best_i] = std::unique_ptr<Worker>(new Worker(*this));
//  workers[best_i]->getEnv() << "GenericMediaServer::getBestThreadedUsageEnvironment: "
//                            << best_i << ", " << best_load << "\n";
  return workers[best_i]->getEnv();
}

void GenericMediaServer::cleanup() {
  if (cleanup_called) return; // cleanup called twice
  cleanup_called = true;
  // This member function must be called in the destructor of any subclass of
  // "GenericMediaServer".  (We don't call this in the destructor of "GenericMediaServer" itself,
  // because by that time, the subclass destructor will already have been called, and this may
  // affect (break) the destruction of the "ClientSession" and "ClientConnection" objects, which
  // themselves will have been subclassed.)

//  envir() << "GenericMediaServer::cleanup: start\n";
  Semaphore sem;
  unsigned int post_count = 0;
  {
    std::map<std::string,std::shared_ptr<ClientSession> > tmp_ClientSessions;
    {
      std::lock_guard<std::recursive_mutex> guard(fClientSessions_mutex);
      tmp_ClientSessions.swap(fClientSessions);
    }
    for (auto &iter: tmp_ClientSessions) {
      if (iter.second) {
        TaskScheduler &scheduler(iter.second->envir().taskScheduler());
        if (!scheduler.isSameThread()) {
          scheduler.executeCommand([clientSession=std::move(iter.second),&sem](uint64_t) mutable {
            clientSession.reset();
            sem.post();
          });
          post_count++;
        }
      }
    }
  }
  while (post_count) {
    sem.wait();
    post_count--;
  }

  {
    std::lock_guard<std::recursive_mutex> lock(fClientConnections_mutex);
    // Close all client connection objects:
    for (auto it(fClientConnections.begin());it!=fClientConnections.end();) {
      GenericMediaServer::ClientConnection *connection(it->second);
      if (connection->envir().taskScheduler().isSameThread()) {
        ++it;
        delete connection;
      } else {
        auto id(it->first);
        ++it;
        connection->envir().taskScheduler().executeCommand([this,id,&sem](uint64_t) {
            std::lock_guard<std::recursive_mutex> guard(fClientConnections_mutex);
            auto it(fClientConnections.find(id));
            if (it != fClientConnections.end()) delete it->second;
            sem.post();
          });
        post_count++;
      }
    }
  }
  while (post_count) {
    sem.wait();
    post_count--;
  }

  {
    std::lock_guard<std::recursive_mutex> lock(sms_mutex);
    // Delete all server media sessions
    fServerMediaSessions.clear();
  }

  for (unsigned int i = 0; i < nr_of_workers; i++) {std::lock_guard<std::mutex> lock(workers_mutex);if (workers[i]) workers[i]->stop();}
  for (unsigned int i = 0; i < nr_of_workers; i++) {std::lock_guard<std::mutex> lock(workers_mutex);if (workers[i]) workers[i]->waitUnitStopped();}
  for (unsigned int i = 0; i < nr_of_workers; i++) {std::lock_guard<std::mutex> lock(workers_mutex);if (workers[i]) workers[i]->joinThread();}
//  envir() << "GenericMediaServer::cleanup: end\n";
}

#define LISTEN_BACKLOG_SIZE 20

int GenericMediaServer::setUpOurSocket(UsageEnvironment& env, Port& ourPort, int domain) {
  int ourSocket = -1;
  
  do {
    // The following statement is enabled by default.
    // Don't disable it (by defining ALLOW_SERVER_PORT_REUSE) unless you know what you're doing.
#if !defined(ALLOW_SERVER_PORT_REUSE) && !defined(ALLOW_RTSP_SERVER_PORT_REUSE)
    // ALLOW_RTSP_SERVER_PORT_REUSE is for backwards-compatibility #####
    NoReuse dummy(env); // Don't use this socket if there's already a local server using it
#endif
    
    ourSocket = setupStreamSocket(env, ourPort, domain, True, True);
        // later fix to support IPv6
    if (ourSocket < 0) break;
    
    // Make sure we have a big send buffer:
    if (!increaseSendBufferTo(env, ourSocket, 50*1024)) break;
    
    // Allow multiple simultaneous connections:
    if (listen(ourSocket, LISTEN_BACKLOG_SIZE) < 0) {
      env.setResultErrMsg("listen() failed: ");
      break;
    }
    
    if (ourPort.num() == 0) {
      // bind() will have chosen a port for us; return it also:
      if (!getSourcePort(env, ourSocket, domain, ourPort)) break;
    }
    
    return ourSocket;
  } while (0);
  
  if (ourSocket != -1) ::closeSocket(ourSocket);
  return -1;
}

void GenericMediaServer::incomingConnectionHandlerIPv4(void* instance, int /*mask*/) {
  GenericMediaServer* server = (GenericMediaServer*)instance;
  server->incomingConnectionHandlerIPv4();
}
void GenericMediaServer::incomingConnectionHandlerIPv6(void* instance, int /*mask*/) {
  GenericMediaServer* server = (GenericMediaServer*)instance;
  server->incomingConnectionHandlerIPv6();
}
void GenericMediaServer::incomingConnectionHandlerIPv4() {
  incomingConnectionHandlerOnSocket(fServerSocketIPv4);
}
void GenericMediaServer::incomingConnectionHandlerIPv6() {
  incomingConnectionHandlerOnSocket(fServerSocketIPv6);
}

void GenericMediaServer::incomingConnectionHandlerOnSocket(int serverSocket) {
  struct sockaddr_storage clientAddr;
  SOCKLEN_T clientAddrLen = sizeof clientAddr;
  int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
envir() << "GenericMediaServer::incomingConnectionHandlerOnSocket: accept(" << serverSocket << ") returned " << clientSocket << "\n";
  if (clientSocket < 0) {
    int err = envir().getErrno();
    if (err != EWOULDBLOCK) {
      envir().setResultErrMsg("accept() failed: ");
    }
    return;
  }
  ignoreSigPipeOnSocket(clientSocket); // so that clients on the same host that are killed don't also kill us
  makeSocketNonBlocking(clientSocket);
// gaj: original 50*1024 is much too small
  increaseSendBufferTo(envir(), clientSocket, 1024*1024);
  
#ifdef DEBUG
  envir() << "accept()ed connection from " << AddressString(clientAddr).val() << "\n";
#endif
  
  // Create a new object for handling this connection:
  (void)createNewClientConnection(clientSocket, clientAddr);
}

void GenericMediaServer
::setTLSFileNames(char const* certFileName, char const* privKeyFileName) {
  delete[] fTLSCertificateFileName; fTLSCertificateFileName = strDup(certFileName);
  delete[] fTLSPrivateKeyFileName; fTLSPrivateKeyFileName = strDup(privKeyFileName);
}


////////// GenericMediaServer::ClientConnection implementation //////////

static GenericMediaServer::ClientConnection::IdType GenerateId(void) {
  static std::atomic<uintptr_t> id_generator(0);
  uintptr_t rval = ++id_generator;
  if (rval == 0) rval = ++id_generator;
  return reinterpret_cast<GenericMediaServer::ClientConnection::IdType>(rval);
}

GenericMediaServer::ClientConnection
::ClientConnection(UsageEnvironment &threaded_env, GenericMediaServer& ourServer, int clientSocket, struct sockaddr_storage const& clientAddr, Boolean useTLS)
  : threaded_env(threaded_env), fOurServer(ourServer), id(GenerateId()), init_command(0), fOurSocket(clientSocket), fClientOutputSocket(clientSocket), fClientAddr(clientAddr), fTLS(threaded_env) {
  fInputTLS = fOutputTLS = &fTLS;
    char peer_host_str[INET6_ADDRSTRLEN + 1];
    char peer_port_str[7 + 1];
    if (getnameinfo((struct sockaddr*)&clientAddr, sizeof(struct sockaddr_storage),
                    peer_host_str, sizeof(peer_host_str), peer_port_str, sizeof(peer_port_str),
                    NI_NUMERICHOST | NI_NUMERICSERV)) {
      strcpy(peer_host_str, "unknown");
      strcpy(peer_port_str, "unknown");
    }
    char sock_host_str[INET6_ADDRSTRLEN + 1];
    char sock_port_str[7 + 1];
    struct sockaddr_storage sock_addr;
    socklen_t sock_addrlen = sizeof(sock_addr);
    if (getsockname(clientSocket, (struct sockaddr*)&sock_addr, &sock_addrlen) ||
        getnameinfo((struct sockaddr*)&sock_addr, sock_addrlen,
                    sock_host_str, sizeof(sock_host_str), sock_port_str, sizeof(sock_port_str),
                    NI_NUMERICHOST | NI_NUMERICSERV)) {
      strcpy(sock_host_str, "unknown");
      strcpy(sock_port_str, "unknown");
    }

    envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::ClientConnection(" << clientSocket
            << "): " << peer_host_str << ":" << peer_port_str
            << "->" << sock_host_str << ":" << sock_port_str
            << "\n";

    envir().taskScheduler().addNrOfUsers(1);
  if (useTLS) {
    // Perform extra processing to handle a TLS connection:
    fTLS.setCertificateAndPrivateKeyFileNames(ourServer.fTLSCertificateFileName,
					      ourServer.fTLSPrivateKeyFileName);
    fTLS.isNeeded = True;

    fTLS.tlsAcceptIsNeeded = True; // call fTLS.accept() the next time the socket is readable
  }
}

void GenericMediaServer::ClientConnection::afterConstruction(void) {
  // Add ourself to our 'client connections' table:
  fOurServer.addClientConnection(this);
  
  // Arrange to handle incoming requests:
  resetRequestBuffer();
  if (envir().taskScheduler().isSameThread()) {
    envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::afterConstruction: calling setBackgroundHandling(" << fOurSocket << ") in same thread\n";
    envir().taskScheduler().setBackgroundHandling(fOurSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
  } else {
    envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::afterConstruction: delegating setBackgroundHandling(" << fOurSocket << ") to thread " << envir().taskScheduler().my_thread_id << "\n";
    init_command = envir().taskScheduler().executeCommand(
      [this](uint64_t) {
        envir().taskScheduler().setBackgroundHandling(fOurSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
        envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::afterConstruction::l: executed delegated setBackgroundHandling(" << fOurSocket << ")\n";
          // Maybe this task will finish fast, and assigning init_command will happen after clearing.
          // Never mind.
          // There is no way cancelling a wrong task: even if there is a new task every nanosecond
          // it will take hundreds of years to wrap around uint64_t.
        init_command = 0;
      });
  }
}

GenericMediaServer::ClientConnection::~ClientConnection() {
    // may be called from another thread
  envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::~ClientConnection\n";
  envir().taskScheduler().cancelCommand(init_command);
  envir().taskScheduler().addNrOfUsers(-1);
  // Remove ourself from the server's 'client connections' hash table before we go:
  fOurServer.removeClientConnection(this);
  
  closeSockets();
}

void GenericMediaServer::ClientConnection::closeSockets() {
  // Turn off background handling on our socket:
  if (fOurSocket>= 0) {
    envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::closeSockets: disableBackgroundHandling(" << fOurSocket << ") and close socket\n";
    envir().taskScheduler().disableBackgroundHandling(fOurSocket);
    ::closeSocket(fOurSocket);
  }

  if (fClientOutputSocket == fOurSocket) fClientOutputSocket = -1;
  fOurSocket = -1;
}

void GenericMediaServer::ClientConnection::incomingRequestHandler(void* instance, int /*mask*/) {
  ClientConnection* connection = (ClientConnection*)instance;
  connection->incomingRequestHandler();
}

void GenericMediaServer::ClientConnection::incomingRequestHandler() {
    // this is called from the tasksceduler, asserting does not hurt:
  envir().taskScheduler().assertSameThread();
  if (fInputTLS->tlsAcceptIsNeeded) { // we need to successfully call fInputTLS->accept() first:
    if (fInputTLS->accept(fOurSocket) <= 0) return; // either an error, or we need to try again later

    fInputTLS->tlsAcceptIsNeeded = False;
    // We can now read data, as usual:
  }

  int bytesRead;
  if (fInputTLS->isNeeded) {
    bytesRead = fInputTLS->read(&fRequestBuffer[fRequestBytesAlreadySeen], fRequestBufferBytesLeft);
  } else {
    struct sockaddr_storage dummy; // 'from' address, meaningless in this case
  
    bytesRead = readSocket(envir(), fOurSocket, &fRequestBuffer[fRequestBytesAlreadySeen], fRequestBufferBytesLeft, dummy);
  }
  if (bytesRead < 0) {
    if (bytesRead == -1) {
      envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::incomingRequestHandler: "
                 "readSocket(" << fOurSocket << ") failed, client hangup\n";
    } else {
      const int errnr = envir().getErrno();
      envir() << "GenericMediaServer::ClientConnection(" << getId() << ")::incomingRequestHandler: "
                 "readSocket(" << fOurSocket << ") failed: "
              << envir().getResultMsg() << "(errno=" << errnr << ")\n";
    }
  }
  handleRequestBytes(bytesRead);
}

void GenericMediaServer::ClientConnection::resetRequestBuffer() {
  fRequestBytesAlreadySeen = 0;
  fRequestBufferBytesLeft = sizeof fRequestBuffer;
}


////////// GenericMediaServer::ClientSession implementation //////////

GenericMediaServer::ClientSession
::ClientSession(UsageEnvironment& threaded_env, GenericMediaServer& ourServer, u_int32_t sessionId)
  : threaded_env(threaded_env), fOurServer(ourServer), fOurSessionId(sessionId),
    fLivenessCheckTask(NULL) {
  noteLiveness();
}

GenericMediaServer::ClientSession::~ClientSession() {
  envir().taskScheduler().assertSameThread();
  // Turn off any liveness checking:
  envir().taskScheduler().unscheduleDelayedTask(fLivenessCheckTask);

#ifdef NOT_NEEDED
  if (fOurServerMediaSession != NULL) {
    fOurServerMediaSession->decrementReferenceCount();
    if (fOurServerMediaSession->referenceCount() == 0
	&& fOurServerMediaSession->deleteWhenUnreferenced()) {
      fOurServer.removeServerMediaSession(fOurServerMediaSession);
      fOurServerMediaSession = NULL;
    }
  }
#endif
}

void GenericMediaServer::ClientSession::deleteThis(void) {
  envir().taskScheduler().assertSameThread();

  // Remove ourself from the server's 'client sessions' hash table before we go:
  char sessionIdStr[8+1];
  sprintf(sessionIdStr, "%08X", fOurSessionId);

  std::lock_guard<std::recursive_mutex> lock(fOurServer.fClientSessions_mutex);
  fOurServer.fClientSessions.erase(sessionIdStr);
  // TODO: Here I should get rid of fOurServerMediaSession so that the liveness task works coorectly 
}

void GenericMediaServer::ClientSession::noteLiveness() {
#ifdef DEBUG
  char const* streamName
    = (fOurServerMediaSession == NULL) ? "???" : fOurServerMediaSession->streamName();
  fprintf(stderr, "Client session (id \"%08X\", stream name \"%s\"): Liveness indication\n",
	  fOurSessionId, streamName);
#endif
  if (fOurServerMediaSession) fOurServerMediaSession->noteLiveness();

  if (fOurServer.fReclamationSeconds > 0) {
    envir().taskScheduler().rescheduleDelayedTask(fLivenessCheckTask,
						  fOurServer.fReclamationSeconds*1000000,
						  (TaskFunc*)livenessTimeoutTask, this);
  }
}

void GenericMediaServer::ClientSession::noteClientLiveness(ClientSession* clientSession) {
  clientSession->noteLiveness();
}

void GenericMediaServer::ClientSession::livenessTimeoutTask(ClientSession* clientSession) {
  // If this gets called, the client session is assumed to have timed out, so delete it:
#ifdef DEBUG
  char const* streamName
    = (clientSession->fOurServerMediaSession == NULL) ? "???" : clientSession->fOurServerMediaSession->streamName();
  fprintf(stderr, "Client session (id \"%08X\", stream name \"%s\") has timed out (due to inactivity)\n",
	  clientSession->fOurSessionId, streamName);
#endif
  clientSession->fLivenessCheckTask = NULL;
  clientSession->deleteThis();
}

std::shared_ptr<GenericMediaServer::ClientSession> GenericMediaServer::createNewClientSessionWithId(UsageEnvironment& env) {
  u_int32_t sessionId;
  char sessionIdStr[8+1];

  std::lock_guard<std::recursive_mutex> lock(fClientSessions_mutex);

  // Choose a random (unused) 32-bit integer for the session id
  // (it will be encoded as a 8-digit hex number).  (We avoid choosing session id 0,
  // because that has a special use by some servers.  Similarly, we avoid choosing the same
  // session id twice in a row.)
  do {
    sessionId = (u_int32_t)our_random32();
    snprintf(sessionIdStr, sizeof sessionIdStr, "%08X", sessionId);
  } while (sessionId == 0 || sessionId == fPreviousClientSessionId
	   || lookupClientSession(sessionIdStr) != NULL);
  fPreviousClientSessionId = sessionId;

  std::shared_ptr<ClientSession> clientSession = createNewClientSession(env, sessionId);
  if (clientSession) fClientSessions[sessionIdStr] = clientSession;

  return clientSession;
}

std::shared_ptr<GenericMediaServer::ClientSession>
GenericMediaServer::lookupClientSession(u_int32_t sessionId) {
  char sessionIdStr[8+1];
  snprintf(sessionIdStr, sizeof sessionIdStr, "%08X", sessionId);
  return lookupClientSession(sessionIdStr);
}

std::shared_ptr<GenericMediaServer::ClientSession>
GenericMediaServer::lookupClientSession(char const* sessionIdStr) {
  std::lock_guard<std::recursive_mutex> lock(fClientSessions_mutex);
  auto it(fClientSessions.find(sessionIdStr));
  if (it != fClientSessions.end()) return it->second;
  return std::shared_ptr<GenericMediaServer::ClientSession>();
}

std::shared_ptr<ServerMediaSession> GenericMediaServer::getServerMediaSession(UsageEnvironment &env,char const* streamName) {
  std::lock_guard<std::recursive_mutex> guard(sms_mutex);
  ServerMediaSessionMap &m(fServerMediaSessions[&env]);
  auto it = m.find(streamName);
  if (it == m.end()) return std::shared_ptr<ServerMediaSession>();
  return it->second.lock();
}


////////// ServerMediaSessionIterator implementation //////////
/*
GenericMediaServer::ServerMediaSessionIterator
::ServerMediaSessionIterator(GenericMediaServer& server)
  : fOurIterator((server.fServerMediaSessions == NULL)
		 ? NULL : HashTable::Iterator::create(*server.fServerMediaSessions)) {
}

GenericMediaServer::ServerMediaSessionIterator::~ServerMediaSessionIterator() {
  delete fOurIterator;
}

ServerMediaSession* GenericMediaServer::ServerMediaSessionIterator::next() {
  if (fOurIterator == NULL) return NULL;

  char const* key; // dummy
  return (ServerMediaSession*)(fOurIterator->next(key));
}
*/

////////// UserAuthenticationDatabase implementation //////////

UserAuthenticationDatabase::UserAuthenticationDatabase(char const* realm,
						       Boolean passwordsAreMD5)
  : fTable(HashTable::create(STRING_HASH_KEYS)),
    fRealm(strDup(realm == NULL ? "LIVE555 Streaming Media" : realm)),
    fPasswordsAreMD5(passwordsAreMD5) {
}

UserAuthenticationDatabase::~UserAuthenticationDatabase() {
  delete[] fRealm;
  
  // Delete the allocated 'password' strings that we stored in the table, and then the table itself:
  char* password;
  std::lock_guard<std::mutex> guard(fTable_mutex);
  while ((password = (char*)fTable->RemoveNext()) != NULL) {
    delete[] password;
  }
  delete fTable;
}

void UserAuthenticationDatabase::addUserRecord(char const* username,
					       char const* password) {
  std::lock_guard<std::mutex> guard(fTable_mutex);
  char* oldPassword = (char*)fTable->Add(username, (void*)(strDup(password)));
  delete[] oldPassword; // if any
}

void UserAuthenticationDatabase::removeUserRecord(char const* username) {
  std::lock_guard<std::mutex> guard(fTable_mutex);
  char* password = (char*)(fTable->Lookup(username));
  fTable->Remove(username);
  delete[] password;
}

char const* UserAuthenticationDatabase::lookupPassword(char const* username) {
  std::lock_guard<std::mutex> guard(fTable_mutex);
  return (char const*)(fTable->Lookup(username));
}
