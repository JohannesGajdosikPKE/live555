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

void GenericMediaServer::addServerMediaSession(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;
  
  char const* sessionName = serverMediaSession->streamName();
  if (sessionName == NULL) sessionName = "";
  std::lock_guard<std::recursive_mutex> guard(internal_mutex);
  removeServerMediaSession(sessionName);
      // in case an existing "ServerMediaSession" with this name already exists
  
  fServerMediaSessions->Add(sessionName, (void*)serverMediaSession);
}

void GenericMediaServer::addServerMediaSessionWithoutRemoving(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;
  
  char const* sessionName = serverMediaSession->streamName();
  if (sessionName == NULL) sessionName = "";
  std::lock_guard<std::recursive_mutex> guard(internal_mutex);
///gaj: belongs to another UsageEnvironment, do not delete:  removeServerMediaSession(sessionName);
      // in case an existing "ServerMediaSession" with this name already exists
  
  fServerMediaSessions->Add(sessionName, (void*)serverMediaSession);
}

void GenericMediaServer
::lookupServerMediaSession(UsageEnvironment& env, char const* streamName,
			   lookupServerMediaSessionCompletionFunc* completionFunc,
			   void* completionClientData,
			   Boolean /*isFirstLookupInSession*/) {
  // Default implementation: Do a synchronous lookup, and call the completion function:
  if (completionFunc != NULL) {
    std::lock_guard<std::recursive_mutex> guard(internal_mutex);
    (*completionFunc)(completionClientData, getServerMediaSession(streamName));
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
  if (serverMediaSession == NULL) return;
  
  fServerMediaSessions->Remove(serverMediaSession->streamName());
  if (serverMediaSession->referenceCount() == 0) {
    Medium::close(serverMediaSession);
  } else {
    serverMediaSession->deleteWhenUnreferenced() = True;
  }
}

void GenericMediaServer::removeServerMediaSession(char const* streamName) {
  lookupServerMediaSession(envir(), streamName, &GenericMediaServer::removeServerMediaSession);
}

void GenericMediaServer::closeAllClientSessionsForServerMediaSession(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;
  
  std::lock_guard<std::recursive_mutex> guard(internal_mutex);
  HashTable::Iterator* iter = HashTable::Iterator::create(*fClientSessions);
  GenericMediaServer::ClientSession* clientSession;
  char const* key; // dummy
  while ((clientSession = (GenericMediaServer::ClientSession*)(iter->next(key))) != NULL) {
    if (clientSession->fOurServerMediaSession == serverMediaSession) {
      delete clientSession;
    }
  }
  delete iter;
}

void GenericMediaServer::closeAllClientSessionsForServerMediaSession(char const* streamName) {
  lookupServerMediaSession(envir(), streamName,
			   &GenericMediaServer::closeAllClientSessionsForServerMediaSession);
}

void GenericMediaServer::deleteServerMediaSession(ServerMediaSession* serverMediaSession) {
  if (serverMediaSession == NULL) return;
  
  std::lock_guard<std::recursive_mutex> guard(internal_mutex);
  closeAllClientSessionsForServerMediaSession(serverMediaSession);
  removeServerMediaSession(serverMediaSession);
}

void GenericMediaServer::deleteServerMediaSession(char const* streamName) {
  lookupServerMediaSession(envir(), streamName, &GenericMediaServer::deleteServerMediaSession);
}

class GenericMediaServer::Worker {
public:
  Worker(void)
    : worker_thread([this](void) {
//        std::cout << "Worker::mainThread(" << std::this_thread::get_id() << "): start" << std::endl << std::flush;
        scheduler = BasicTaskScheduler::createNew();
        scheduler->assert_threads = true;
//        std::cout << "Worker::mainThread(" << std::this_thread::get_id() << "): scheduler created" << std::endl << std::flush;
        env = new DeletableUsageEnvironment(*scheduler);
        {
          std::unique_lock<std::mutex> lck(mtx);
          watchVariable = 0;
          cv.notify_one();
        }
        env->taskScheduler().doEventLoop(&watchVariable);
        delete env; env = nullptr;
        delete scheduler; scheduler = nullptr;
      }) {
    std::unique_lock<std::mutex> lck(mtx);
    while (watchVariable) cv.wait(lck);
  }
  ~Worker(void) {
    worker_thread.join();
  }
  void stop(void) {watchVariable = 1;}
  UsageEnvironment& getEnv(void) const {return *env;}
  int getLoad(void) const {return scheduler->addNrOfUsers(0);}
private:
  BasicTaskScheduler *scheduler = nullptr;
  struct DeletableUsageEnvironment : public BasicUsageEnvironment {
    DeletableUsageEnvironment(TaskScheduler& s) : BasicUsageEnvironment(s) {}
  } *env = nullptr;
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
    fServerMediaSessions(HashTable::create(STRING_HASH_KEYS)),
    fClientConnections(HashTable::create(ONE_WORD_HASH_KEYS)),
    fClientSessions(HashTable::create(STRING_HASH_KEYS)),
    fPreviousClientSessionId(0),
    nr_of_workers(GetNrOfCores()),
    workers(new Worker[nr_of_workers])
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

UsageEnvironment &GenericMediaServer::getBestThreadedUsageEnvironment(void) {
  Worker *best_worker = workers;
  int best_load = best_worker->getLoad();
  for (int i = 1; i < nr_of_workers; i++) {
    const int load = workers[i].getLoad();
    if (load < best_load) {
      best_load = load;
      best_worker = workers + i;
    }
  }
//fprintf(stderr,"getBestThreadedUsageEnvironment: %d with load %d\n", best_worker-workers, best_load);
  return best_worker->getEnv();
}

void GenericMediaServer::cleanup() {
  // This member function must be called in the destructor of any subclass of
  // "GenericMediaServer".  (We don't call this in the destructor of "GenericMediaServer" itself,
  // because by that time, the subclass destructor will already have been called, and this may
  // affect (break) the destruction of the "ClientSession" and "ClientConnection" objects, which
  // themselves will have been subclassed.)

  for (int i = 0; i < nr_of_workers; i++) workers[i].stop();

  std::lock_guard<std::recursive_mutex> guard(internal_mutex);

  // Close all client session objects:
  GenericMediaServer::ClientSession* clientSession;
  while ((clientSession = (GenericMediaServer::ClientSession*)fClientSessions->getFirst()) != NULL) {
    delete clientSession;
  }
  delete fClientSessions;
  
  // Close all client connection objects:
  GenericMediaServer::ClientConnection* connection;
  while ((connection = (GenericMediaServer::ClientConnection*)fClientConnections->getFirst()) != NULL) {
    delete connection;
  }
  delete fClientConnections;
  
  // Delete all server media sessions
  ServerMediaSession* serverMediaSession;
  while ((serverMediaSession = (ServerMediaSession*)fServerMediaSessions->getFirst()) != NULL) {
    removeServerMediaSession(serverMediaSession); // will delete it, because it no longer has any 'client session' objects using it
  }
  delete fServerMediaSessions;
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
  : threaded_env(threaded_env), fOurServer(ourServer), fOurSocket(clientSocket), fClientAddr(clientAddr) {
    envir().taskScheduler().addNrOfUsers(1);
}

void GenericMediaServer::ClientConnection::afterConstruction(void) {
  // Add ourself to our 'client connections' table:
  fOurServer.addClientConnection(this);
  
  // Arrange to handle incoming requests:
  resetRequestBuffer();
  envir().taskScheduler().executeCommand(
    [this]() {
      envir().taskScheduler().setBackgroundHandling(fOurSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
    });
}

GenericMediaServer::ClientConnection::~ClientConnection() {
  envir().taskScheduler().assertSameThread();
  envir().taskScheduler().addNrOfUsers(-1);
  // Remove ourself from the server's 'client connections' hash table before we go:
  fOurServer.removeClientConnection(this);
  
  closeSockets();
}

void GenericMediaServer::ClientConnection::closeSockets() {
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
  fOurServer.fClientSessions->Remove(sessionIdStr);
  
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

  std::lock_guard<std::recursive_mutex> guard(internal_mutex);

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
  std::lock_guard<std::recursive_mutex> guard(internal_mutex);
  return (GenericMediaServer::ClientSession*)fClientSessions->Lookup(sessionIdStr);
}

ServerMediaSession* GenericMediaServer::getServerMediaSession(char const* streamName) {
  std::lock_guard<std::recursive_mutex> guard(internal_mutex);
  return (ServerMediaSession*)(fServerMediaSessions->Lookup(streamName));
}


////////// ServerMediaSessionIterator implementation //////////

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
