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
// Copyright (c) 1996-2021 Live Networks, Inc.  All rights reserved.
// A generic media server class, used to implement a RTSP server, and any other server that uses
//  "ServerMediaSession" objects to describe media to be served.
// Implementation

#include "GenericMediaServer.hh"
#include <GroupsockHelper.hh>
#include <BasicUsageEnvironment.hh>

#include <thread>
#include <iostream>

#if defined(__WIN32__) || defined(_WIN32) || defined(_QNX4)
#define snprintf _snprintf
#endif

////////// GenericMediaServer implementation //////////

static void removeServerMediaSessionImpl(ServerMediaSession* serverMediaSession) {
    // maybe envir() is already destroed, dont use it
  if (serverMediaSession->referenceCount() == 0) {
//    serverMediaSession->envir() << "removeServerMediaSessionImpl(" << serverMediaSession << "): calling Medium::close\n";
    Medium::close(serverMediaSession);
  } else {
//    serverMediaSession->envir() << "removeServerMediaSessionImpl(" << serverMediaSession << "): setting deleteWhenUnreferenced\n";
    serverMediaSession->deleteWhenUnreferenced() = True;
  }
}

void GenericMediaServer::addServerMediaSession(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;
  
  char const* sessionName = serverMediaSession->streamName();
  if (sessionName == NULL) sessionName = "";
  ServerMediaSession *old_sms = nullptr;
  {
    std::lock_guard<std::recursive_mutex> guard(sms_mutex);
    const auto rc
      = fServerMediaSessions[&serverMediaSession->envir()].insert(
          std::pair<std::string,ServerMediaSession*>(sessionName,serverMediaSession));
    if (!rc.second) {
      old_sms = rc.first->second;
      rc.first->second = serverMediaSession;
    }
  }
  if (old_sms) {
    if (serverMediaSession->envir().taskScheduler().isSameThread()) {
      removeServerMediaSessionImpl(old_sms);
    } else {
      Semaphore sem;
      serverMediaSession->envir().taskScheduler().executeCommand(
        [serverMediaSession,old_sms,&sem](uint64_t) {
          removeServerMediaSessionImpl(old_sms);
          sem.post();
        });
      sem.wait();
    }
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
  void (GenericMediaServer::*fMemberFunc)(ServerMediaSession*);
};

static void lsmsMemberFunctionCompletionFunc(void* clientData, ServerMediaSession* sessionLookedUp) {
  lsmsMemberFunctionRecord* memberFunctionRecord = (lsmsMemberFunctionRecord*)clientData;
  (memberFunctionRecord->fServer->*(memberFunctionRecord->fMemberFunc))(sessionLookedUp);
  delete memberFunctionRecord;
}

void GenericMediaServer
::lookupServerMediaSession(UsageEnvironment& env, char const* streamName,
			   void (GenericMediaServer::*memberFunc)(ServerMediaSession*)) {
  struct lsmsMemberFunctionRecord* memberFunctionRecord = new struct lsmsMemberFunctionRecord;
  memberFunctionRecord->fServer = this;
  memberFunctionRecord->fMemberFunc = memberFunc;
  
  GenericMediaServer
    ::lookupServerMediaSession(env, streamName,
			       lsmsMemberFunctionCompletionFunc, memberFunctionRecord);
}

void GenericMediaServer::removeServerMediaSession(ServerMediaSession* serverMediaSession) {
//  envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ") start\n";
  if (serverMediaSession == NULL) return;
  {
    std::lock_guard<std::recursive_mutex> guard(sms_mutex);
    fServerMediaSessions[&serverMediaSession->envir()].erase(serverMediaSession->streamName());
  }

  if (serverMediaSession->envir().taskScheduler().isSameThread()) {
      // the desructor of a Medium must be called from its own UsageEnvironment,
      // because it unscedules a task:
//    envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << "): removing in this thread\n";
    removeServerMediaSessionImpl(serverMediaSession);
  } else {
    Semaphore sem;
//    envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << "): delegating to sms thread\n";
    serverMediaSession->envir().taskScheduler().executeCommand(
      [serverMediaSession,&sem](uint64_t) {
        serverMediaSession->envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ")::l: removing in this thread\n";
        removeServerMediaSessionImpl(serverMediaSession);
///        serverMediaSession->envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ")::l: removed in this thread\n";
///        sem.post();
///        serverMediaSession->envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ")::l: sem posted\n";
      });
//    envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << "): waiting for sem\n";
///    sem.wait();
//    envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << "): waited for sem\n";
  }
//  envir() << "GenericMediaServer::removeServerMediaSession(" << serverMediaSession << ") end\n";
}

void GenericMediaServer::removeServerMediaSession(UsageEnvironment &env, char const* streamName) {
//  env << "GenericMediaServer::removeServerMediaSession(" << streamName << ") start\n";
  lookupServerMediaSession(env, streamName, &GenericMediaServer::removeServerMediaSession);
//  env << "GenericMediaServer::removeServerMediaSession(" << streamName << ") end\n";
}

void GenericMediaServer::closeAllClientSessionsForServerMediaSession(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;

  Semaphore sem;
  unsigned int post_count = 0;
  {
  std::lock_guard<std::recursive_mutex> guard(fClientSessions_mutex);
  HashTable::Iterator* iter = HashTable::Iterator::create(*fClientSessions);
  GenericMediaServer::ClientSession* clientSession;
  char const* key; // dummy
  while ((clientSession = (GenericMediaServer::ClientSession*)(iter->next(key))) != NULL) {
    if (clientSession->fOurServerMediaSession == serverMediaSession) {
      if (clientSession->envir().taskScheduler().isSameThread()) {
        delete clientSession;
      } else {
        clientSession->envir().taskScheduler().executeCommand([clientSession,&sem](uint64_t) {
          delete clientSession;
          sem.post();
        });
        post_count++;
      }
    }
  }
  delete iter;
  }
  while (post_count) {
    sem.wait();
    post_count--;
  }
}

void GenericMediaServer::closeAllClientSessionsForServerMediaSession(char const* streamName) {
  lookupServerMediaSession(envir(), streamName,
			   &GenericMediaServer::closeAllClientSessionsForServerMediaSession);
}

void GenericMediaServer::deleteServerMediaSession(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;
  
  {
    std::lock_guard<std::recursive_mutex> guard(fClientConnections_mutex);
    closeAllClientSessionsForServerMediaSession(serverMediaSession);
  }
  removeServerMediaSession(serverMediaSession);
}

void GenericMediaServer::deleteServerMediaSession(UsageEnvironment &env, char const* streamName) {
  env << "GenericMediaServer::deleteServerMediaSession(" << streamName << ") start\n";
  lookupServerMediaSession(env, streamName, &GenericMediaServer::deleteServerMediaSession);
  env << "GenericMediaServer::deleteServerMediaSession(" << streamName << ") end\n";
}

void GenericMediaServer::deleteAllServerMediaSessions(char const* streamName) {
      // delete seesions with this name from all UsageEnvironments
  envir() << "GenericMediaServer::deleteAllServerMediaSessions(" << streamName << ") start\n";
  std::lock_guard<std::recursive_mutex> guard(sms_mutex);
  for (auto &m : fServerMediaSessions) {
    auto it = m.second.find(streamName);
    if (it != m.second.end()) {
      deleteServerMediaSession(it->second);
    }
  }
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
        {
          std::lock_guard<std::mutex> lck(mtx);
          watchVariable = 0;
          cv.notify_one();
        }
        (*env) << "GenericMediaServer::Worker::mainThread: start\n";
        env->taskScheduler().doEventLoop(&watchVariable);
        (*env) << "GenericMediaServer::Worker::mainThread: end\n";
        if (!env->reclaim()) abort();
        env = nullptr;
        delete scheduler; scheduler = nullptr;
      }) {
    std::unique_lock<std::mutex> lck(mtx);
    while (watchVariable) cv.wait(lck);
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
  UsageEnvironment& getEnv(void) const {return *env;}
  int getLoad(void) const {return scheduler->addNrOfUsers(0);}
private:
  BasicTaskScheduler *scheduler = nullptr;
  UsageEnvironment *env = nullptr;
  char volatile watchVariable = 1;
  std::thread worker_thread;
    // mutex and contition variable only to be able to wait for thread to start:
  std::mutex mtx;
  std::condition_variable cv;
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
    fClientConnections(HashTable::create(ONE_WORD_HASH_KEYS)),
    fClientSessions(HashTable::create(STRING_HASH_KEYS)),
    fPreviousClientSessionId(0),
    nr_of_workers(GetNrOfCores()),
    workers(new std::unique_ptr<Worker>[nr_of_workers])
{
//fprintf(stderr,"GenericMediaServer::GenericMediaServer: %u workers\n", nr_of_workers);
  ignoreSigPipeOnSocket(fServerSocketIPv4); // so that clients on the same host that are killed don't also kill us
  ignoreSigPipeOnSocket(fServerSocketIPv6); // ditto
  
  // Arrange to handle connections from others:
  env.taskScheduler().turnOnBackgroundReadHandling(fServerSocketIPv4, incomingConnectionHandlerIPv4, this);
  env.taskScheduler().turnOnBackgroundReadHandling(fServerSocketIPv6, incomingConnectionHandlerIPv6, this);
}

GenericMediaServer::~GenericMediaServer() {
  delete[] workers;
  // Turn off background read handling:
  envir().taskScheduler().turnOffBackgroundReadHandling(fServerSocketIPv4);
  ::closeSocket(fServerSocketIPv4);
  envir().taskScheduler().turnOffBackgroundReadHandling(fServerSocketIPv6);
  ::closeSocket(fServerSocketIPv6);
}

UsageEnvironment *GenericMediaServer::createNewUsageEnvironment(TaskScheduler &scheduler) {
  return BasicUsageEnvironment::createNew(scheduler);
}

UsageEnvironment &GenericMediaServer::getBestThreadedUsageEnvironment(void) {
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
  if (!fClientSessions) return; // cleanup called twice
  // This member function must be called in the destructor of any subclass of
  // "GenericMediaServer".  (We don't call this in the destructor of "GenericMediaServer" itself,
  // because by that time, the subclass destructor will already have been called, and this may
  // affect (break) the destruction of the "ClientSession" and "ClientConnection" objects, which
  // themselves will have been subclassed.)

  Semaphore sem;
  unsigned int post_count = 0;
  {
    std::lock_guard<std::recursive_mutex> guard(fClientSessions_mutex);
    // Close all client session objects:
    GenericMediaServer::ClientSession* clientSession;
    while ((clientSession = (GenericMediaServer::ClientSession*)fClientSessions->getFirst()) != NULL) {
      char sessionIdStr[8 + 1];
      sprintf(sessionIdStr, "%08X", clientSession->fOurSessionId);
      if (clientSession->envir().taskScheduler().isSameThread()) {
        delete clientSession;
      } else {
        clientSession->envir().taskScheduler().executeCommand(
          [clientSession,&sem,&post_count](uint64_t) {
            delete clientSession;
            post_count++;
            sem.post();
          });
      }
      fClientSessions->Remove(sessionIdStr);
    }
  }

  {
    std::lock_guard<std::recursive_mutex> lock(fClientConnections_mutex);
    // Close all client connection objects:
    GenericMediaServer::ClientConnection* connection;
    while ((connection = (GenericMediaServer::ClientConnection*)fClientConnections->getFirst()) != NULL) {
      if (connection->envir().taskScheduler().isSameThread()) {
        delete connection;
      } else {
        connection->envir().taskScheduler().executeCommand(
          [connection,&sem,&post_count](uint64_t) {
            delete connection;
            post_count++;
            sem.post();
          });
      }
      removeClientConnection(connection);
    }
  }
  {
    std::lock_guard<std::recursive_mutex> lock(sms_mutex);
    // Delete all server media sessions
    ServerMediaSession* serverMediaSession;
    for (auto e : fServerMediaSessions) {
      while (!e.second.empty()) {
        ServerMediaSession *serverMediaSession = e.second.begin()->second;
        if (e.first->taskScheduler().isSameThread()) {
          removeServerMediaSessionImpl(serverMediaSession);
        } else {
          e.first->taskScheduler().executeCommand(
            [serverMediaSession,&sem,&post_count](uint64_t) {
              removeServerMediaSessionImpl(serverMediaSession);
              post_count++;
              sem.post();
            });
        }
        e.second.erase(e.second.begin());
      }
    }
  }

  while (post_count >= 0) {
    sem.wait();
    post_count--;
  }

  for (unsigned int i = 0; i < nr_of_workers; i++) if (workers[i]) workers[i]->stop();
  for (unsigned int i = 0; i < nr_of_workers; i++) if (workers[i]) workers[i]->joinThread();
  delete fClientSessions; fClientSessions = nullptr;
  delete fClientConnections; fClientConnections = nullptr;
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


////////// GenericMediaServer::ClientConnection implementation //////////

GenericMediaServer::ClientConnection
::ClientConnection(UsageEnvironment &threaded_env, GenericMediaServer& ourServer, int clientSocket, struct sockaddr_storage const& clientAddr)
  : threaded_env(threaded_env), fOurServer(ourServer), init_command(0), fOurSocket(clientSocket), fClientAddr(clientAddr) {
    envir() << "GenericMediaServer::ClientConnection(" << this << ")::ClientConnection(" << clientSocket << ")\n";
    envir().taskScheduler().addNrOfUsers(1);
}

void GenericMediaServer::ClientConnection::afterConstruction(void) {
  // Add ourself to our 'client connections' table:
  fOurServer.addClientConnection(this);
  
  // Arrange to handle incoming requests:
  resetRequestBuffer();
  envir() << "GenericMediaServer::ClientConnection(" << this << ")::afterConstruction: setBackgroundHandling(" << fOurSocket << ")\n";
  if (envir().taskScheduler().isSameThread()) {
    envir().taskScheduler().setBackgroundHandling(fOurSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
  } else {
    init_command = envir().taskScheduler().executeCommand(
      [this](uint64_t) {
        envir().taskScheduler().setBackgroundHandling(fOurSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
          // Maybe this task will finish fast, and assigning init_command will happen after clearing.
          // Never mind.
          // There is no way cancelling a wrong task: even if there is a new task every nanosecond
          // it will take hundreds of years to wrap around uint64_t.
        init_command = 0;
      });
  }
}

GenericMediaServer::ClientConnection::~ClientConnection() {
  envir().taskScheduler().assertSameThread();
  envir().taskScheduler().cancelCommand(init_command);
  envir() << "GenericMediaServer::ClientConnection(" << this << ")::~ClientConnection\n";
  envir().taskScheduler().assertSameThread();
  envir().taskScheduler().addNrOfUsers(-1);
  // Remove ourself from the server's 'client connections' hash table before we go:
  fOurServer.removeClientConnection(this);
  
  closeSockets();
}

void GenericMediaServer::ClientConnection::closeSockets() {
  envir() << "GenericMediaServer::ClientConnection(" << this << ")::closeSockets: disableBackgroundHandling(" << fOurSocket << ")\n";
  // Turn off background handling on our socket:
  envir().taskScheduler().disableBackgroundHandling(fOurSocket);
  if (fOurSocket>= 0) ::closeSocket(fOurSocket);

  fOurSocket = -1;
}

void GenericMediaServer::ClientConnection::incomingRequestHandler(void* instance, int /*mask*/) {
  ClientConnection* connection = (ClientConnection*)instance;
  connection->incomingRequestHandler();
}

void GenericMediaServer::ClientConnection::incomingRequestHandler() {
  envir().taskScheduler().assertSameThread();
  struct sockaddr_storage dummy; // 'from' address, meaningless in this case
  
  int bytesRead = readSocket(envir(), fOurSocket, &fRequestBuffer[fRequestBytesAlreadySeen], fRequestBufferBytesLeft, dummy);
  if (bytesRead < 0) {
    envir() << "GenericMediaServer::ClientConnection(" << this << ")::incomingRequestHandler: "
               "readSocket(" << fOurSocket << ") failed, probably client hangup: "
            << envir().getResultMsg() << "\n";
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
  : threaded_env(threaded_env), fOurServer(ourServer), fOurSessionId(sessionId), fOurServerMediaSession(NULL),
    fLivenessCheckTask(NULL) {
  noteLiveness();
}

GenericMediaServer::ClientSession::~ClientSession() {
  // Turn off any liveness checking:
  envir().taskScheduler().unscheduleDelayedTask(fLivenessCheckTask);

  // Remove ourself from the server's 'client sessions' hash table before we go:
  char sessionIdStr[8+1];
  sprintf(sessionIdStr, "%08X", fOurSessionId);
  {
  std::lock_guard<std::recursive_mutex> lock(fOurServer.fClientSessions_mutex);
  fOurServer.fClientSessions->Remove(sessionIdStr);
  }
  if (fOurServerMediaSession != NULL) {
    fOurServerMediaSession->decrementReferenceCount();
    if (fOurServerMediaSession->referenceCount() == 0
	&& fOurServerMediaSession->deleteWhenUnreferenced()) {
      fOurServer.removeServerMediaSession(fOurServerMediaSession);
      fOurServerMediaSession = NULL;
    }
  }
}

void GenericMediaServer::ClientSession::noteLiveness() {
#ifdef DEBUG
  char const* streamName
    = (fOurServerMediaSession == NULL) ? "???" : fOurServerMediaSession->streamName();
  fprintf(stderr, "Client session (id \"%08X\", stream name \"%s\"): Liveness indication\n",
	  fOurSessionId, streamName);
#endif
  if (fOurServerMediaSession != NULL) fOurServerMediaSession->noteLiveness();

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
  delete clientSession;
}

GenericMediaServer::ClientSession* GenericMediaServer::createNewClientSessionWithId(UsageEnvironment& env) {
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

  ClientSession* clientSession = createNewClientSession(env, sessionId);
  if (clientSession != NULL) fClientSessions->Add(sessionIdStr, clientSession);

  return clientSession;
}

GenericMediaServer::ClientSession*
GenericMediaServer::lookupClientSession(u_int32_t sessionId) {
  char sessionIdStr[8+1];
  snprintf(sessionIdStr, sizeof sessionIdStr, "%08X", sessionId);
  return lookupClientSession(sessionIdStr);
}

GenericMediaServer::ClientSession*
GenericMediaServer::lookupClientSession(char const* sessionIdStr) {
  std::lock_guard<std::recursive_mutex> lock(fClientSessions_mutex);
  return (GenericMediaServer::ClientSession*)fClientSessions->Lookup(sessionIdStr);
}

ServerMediaSession* GenericMediaServer::getServerMediaSession(UsageEnvironment &env,char const* streamName) {
  std::lock_guard<std::recursive_mutex> guard(sms_mutex);
  ServerMediaSessionMap &m(fServerMediaSessions[&env]);
  auto it = m.find(streamName);
  if (it == m.end()) return nullptr;
  return it->second;
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
