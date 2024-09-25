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
// C++ header

#ifndef _GENERIC_MEDIA_SERVER_HH
#define _GENERIC_MEDIA_SERVER_HH

#ifndef _MEDIA_HH
#include "Media.hh"
#endif
#ifndef _SERVER_MEDIA_SESSION_HH
#include "ServerMediaSession.hh"
#endif

#ifndef REQUEST_BUFFER_SIZE
#define REQUEST_BUFFER_SIZE 20000 // for incoming requests
#endif
#ifndef RESPONSE_BUFFER_SIZE
#define RESPONSE_BUFFER_SIZE 20000
#endif

#include <mutex>
#include <condition_variable>
#include <memory>
#include <map>
#include <atomic>

// Typedef for a handler function that gets called when "lookupServerMediaSession()"
// (defined below) completes:
typedef void lookupServerMediaSessionCompletionFunc(void* clientData,
						    const std::shared_ptr<ServerMediaSession> &sessionLookedUp);

class GenericMediaServer: public Medium {
public:
  virtual void addServerMediaSession(const std::shared_ptr<ServerMediaSession> &serverMediaSession);

  virtual void lookupServerMediaSession(UsageEnvironment &env, char const* streamName,
					lookupServerMediaSessionCompletionFunc* completionFunc,
					void* completionClientData,
					Boolean isFirstLookupInSession = True);
      // Note: This is a virtual function, so can be reimplemented by subclasses.
  void lookupServerMediaSession(UsageEnvironment& env, char const* streamName,
				void (GenericMediaServer::*memberFunc)(const std::shared_ptr<ServerMediaSession> &));
      // Special case of "lookupServerMediaSession()" where the 'completion function' is a
      // member function of "GenericMediaServer" (and the 'completion client data' is "this".)

  void removeServerMediaSession(const ServerMediaSession &serverMediaSession);
      // Removes the "ServerMediaSession" object from our lookup table, so it will no longer be accessible by new clients.
      // (However, any *existing* client sessions that use this "ServerMediaSession" object will continue streaming.
      //  The "ServerMediaSession" object will not get deleted until all of these client sessions have closed.)
      // (To both delete the "ServerMediaSession" object *and* close all client sessions that use it,
      //  call "deleteServerMediaSession(serverMediaSession)" instead.)
#ifdef NOT_NEEDED
  virtual void removeServerMediaSession(UsageEnvironment &env, char const* streamName);
     // ditto
#endif

  void closeAllClientSessionsForServerMediaSession(const ServerMediaSession &serverMediaSession);
      // Closes (from the server) all client sessions that are currently using this "ServerMediaSession" object.
      // Note, however, that the "ServerMediaSession" object remains accessible by new clients.
#ifdef NOT_NEEDED
  virtual void closeAllClientSessionsForServerMediaSession(char const* streamName);
     // ditto
#endif

  void deleteServerMediaSession(const std::shared_ptr<ServerMediaSession> &serverMediaSession);
      // Equivalent to:
      //     "closeAllClientSessionsForServerMediaSession(serverMediaSession); removeServerMediaSession(serverMediaSession);"
#ifdef NOT_NEEDED
  virtual void deleteServerMediaSession(UsageEnvironment &env, char const* streamName);
      // Equivalent to:
      //     "closeAllClientSessionsForServerMediaSession(streamName); removeServerMediaSession(streamName);
#endif

  virtual void deleteAllServerMediaSessions(char const* streamName);
      // delete seesions with this name from all UsageEnvironments

  unsigned numClientSessions() const {
    std::lock_guard<std::recursive_mutex> lock(fClientSessions_mutex);
    return (unsigned)fClientSessions.size();
  }

  // https://stackoverflow.com/questions/4792449/c0x-has-no-semaphores-how-to-synchronize-threads
  class Semaphore {
      std::mutex m;
      std::condition_variable cv;
      unsigned long count_ = 0;
  public:
      void post(void) {
          std::lock_guard<std::mutex> lock(m);
          ++count_;
          cv.notify_one();
      }
      void wait(void) {
          std::unique_lock<std::mutex> lock(m);
          while (!count_) // Handle spurious wake-ups.
              cv.wait(lock);
          --count_;
      }
  };

protected:
  GenericMediaServer(UsageEnvironment& env, int ourSocketIPv4, int ourSocketIPv6, Port ourPort,
                     unsigned reclamationSeconds);
      // If "reclamationSeconds" > 0, then the "ClientSession" state for each client will get
      // reclaimed if no activity from the client is detected in at least "reclamationSeconds".
  // we're an abstract base class
  virtual ~GenericMediaServer();
  void cleanup(); // MUST be called in the destructor of any subclass of us

  static int setUpOurSocket(UsageEnvironment& env, Port& ourPort, int domain);

  static void incomingConnectionHandlerIPv4(void*, int /*mask*/);
  static void incomingConnectionHandlerIPv6(void*, int /*mask*/);
  void incomingConnectionHandlerIPv4();
  void incomingConnectionHandlerIPv6();
  void incomingConnectionHandlerOnSocket(int serverSocket);

  void setTLSFileNames(char const* certFileName, char const* privKeyFileName);

public: // should be protected, but some old compilers complain otherwise
  // The state of a TCP connection used by a client:
  class ClientConnection : public std::enable_shared_from_this<ClientConnection> {
  protected:
    ClientConnection(UsageEnvironment& threaded_env,GenericMediaServer& ourServer,
		     int clientSocket, struct sockaddr_storage const& clientAddr,
		     Boolean useTLS);
    void afterConstruction(void);
  public:
    virtual ~ClientConnection();
    UsageEnvironment& envir() { return threaded_env; }
    typedef void *IdType;
    IdType getId(void) const {return id;}
    int getSocket(void) const {return fOurSocket;}
  protected:
    void closeSockets();

    static void incomingRequestHandler(void*, int /*mask*/);
    void incomingRequestHandler();
    virtual void handleRequestBytes(int newBytesRead) = 0;
    void resetRequestBuffer();

  protected:
    UsageEnvironment &threaded_env;
    void lookupServerMediaSession(UsageEnvironment& env, char const* streamName,
                                  void *context,
                                  lookupServerMediaSessionCompletionFunc* completionFunc,
                                  Boolean isFirstLookupInSession = True) {
      fOurServer.lookupServerMediaSession(env, streamName, completionFunc, context, isFirstLookupInSession);
    }
    void removeServerMediaSession(const ServerMediaSession &serverMediaSession) {
      fOurServer.removeServerMediaSession(serverMediaSession);
    }
    void removeFromServer(void) {
      fOurServer.removeClientConnection(this);
    }
  private:
      // tread safety: do not allow wild access to fOurServer
    GenericMediaServer& fOurServer;
    const IdType id;
    std::atomic<uint64_t> init_command;
  protected:
    int fOurSocket;
    int fClientOutputSocket; // for RTSPClientConnection only
    struct sockaddr_storage fClientAddr;
    unsigned char fRequestBuffer[REQUEST_BUFFER_SIZE];
    unsigned char fResponseBuffer[RESPONSE_BUFFER_SIZE];
    unsigned fRequestBytesAlreadySeen, fRequestBufferBytesLeft;

    // Optional support for TLS:
    ServerTLSState fTLS;
    ServerTLSState* fInputTLS; // by default, just points to "fTLS", but subclasses may change
    ServerTLSState* fOutputTLS; // ditto
  };

  // The state of an individual client session (using one or more sequential TCP connections) handled by a server:
  class ClientSession {
  public:
    void deleteThis(void);
    u_int32_t getOurSessionId(void) const {return fOurSessionId;}
    std::shared_ptr<ServerMediaSession> getOurServerMediaSession(void) const {return fOurServerMediaSession;}
  protected:
    ClientSession(UsageEnvironment& threaded_env, GenericMediaServer& ourServer, u_int32_t sessionId);
    virtual ~ClientSession();

  public:
    UsageEnvironment &envir() {return threaded_env;}
    void noteLiveness();
  protected:
    static void noteClientLiveness(ClientSession* clientSession);
    static void livenessTimeoutTask(ClientSession* clientSession);

  protected:
    UsageEnvironment &threaded_env;
    GenericMediaServer& fOurServer;
    const u_int32_t fOurSessionId;
    std::shared_ptr<ServerMediaSession> fOurServerMediaSession;
    TaskToken fLivenessCheckTask;
  };

protected:
  virtual std::shared_ptr<ClientConnection> createNewClientConnection(int clientSocket, struct sockaddr_storage const& clientAddr) = 0;
  virtual std::shared_ptr<ClientSession> createNewClientSession(UsageEnvironment& env, u_int32_t sessionId) = 0;

  std::shared_ptr<ClientSession> createNewClientSessionWithId(UsageEnvironment& env);
      // Generates a new (unused) random session id, and calls the "createNewClientSession()"
      // virtual function with this session id as parameter.

  // Lookup a "ClientSession" object by sessionId (integer, and string):
  std::shared_ptr<ClientSession> lookupClientSession(u_int32_t sessionId);
  std::shared_ptr<ClientSession> lookupClientSession(char const* sessionIdStr);

  // An iterator over our "ServerMediaSession" objects:
  // while using you must lock the sms_mutex
/*  class ServerMediaSessionIterator {
  public:
    ServerMediaSessionIterator(GenericMediaServer& server);
    virtual ~ServerMediaSessionIterator();
    ServerMediaSession* next();
  private:
    HashTable::Iterator* fOurIterator;
  };
*/
protected:
    // The basic, synchronous "ServerMediaSession" lookup operation; only for subclasses:
  std::shared_ptr<ServerMediaSession> getServerMediaSession(UsageEnvironment &env,char const* streamName);
  
  std::shared_ptr<ClientConnection> getClientConnection(ClientConnection::IdType id) const {
    std::lock_guard<std::recursive_mutex> lock(fClientConnections_mutex);
    auto it(fClientConnections.find(id));
    if (it != fClientConnections.end()) return it->second;
    return std::shared_ptr<ClientConnection>();
  }

protected:
  const int fServerSocketIPv4;
  const int fServerSocketIPv6;
  const Port fServerPort;
  const unsigned fReclamationSeconds;

  UsageEnvironment& getBestThreadedUsageEnvironment(void);

  virtual UsageEnvironment *createNewUsageEnvironment(TaskScheduler &scheduler);
  void addClientConnection(const std::shared_ptr<ClientConnection> &c) {
    std::lock_guard<std::recursive_mutex> guard(fClientConnections_mutex);
    auto rc(fClientConnections.insert(std::pair<ClientConnection::IdType,std::shared_ptr<ClientConnection> >(c->getId(),c)));
    if (!rc.second) {
      envir() << "GenericMediaServer::addClientConnection(" << c->getId() << "): fatal: double id\n";
      abort();
    }
  }
  void removeClientConnection(ClientConnection *c) {
    std::lock_guard<std::recursive_mutex> guard(fClientConnections_mutex);
    fClientConnections.erase(c->getId());
  }
  
  typedef std::map<std::string,std::weak_ptr<ServerMediaSession> > ServerMediaSessionMap;
  typedef std::map<UsageEnvironment*,ServerMediaSessionMap> ServerMediaSessionEnvMap;
  ServerMediaSessionEnvMap fServerMediaSessions; // maps 'stream name' strings to "ServerMediaSession" objects
  mutable std::recursive_mutex sms_mutex; // protects fServerMediaSessions only
  std::map<ClientConnection::IdType, std::shared_ptr<ClientConnection> > fClientConnections; // the "ClientConnection" objects that we're using
  mutable std::recursive_mutex fClientConnections_mutex; // protects fClientConnections
    // maps 'session id' strings to "ClientSession" objects
  mutable std::recursive_mutex fClientSessions_mutex; // protects fClientSessions
  std::map<std::string,std::shared_ptr<ClientSession> > fClientSessions;
  u_int32_t fPreviousClientSessionId;
  char const* fTLSCertificateFileName;
  char const* fTLSPrivateKeyFileName;

  const unsigned int nr_of_workers;
  class Worker;
  std::mutex workers_mutex;
  std::unique_ptr<Worker> *const workers;
  bool cleanup_called;
};

// A data structure used for optional user/password authentication:

class UserAuthenticationDatabase {
public:
  UserAuthenticationDatabase(char const* realm = NULL,
			     Boolean passwordsAreMD5 = False);
    // If "passwordsAreMD5" is True, then each password stored into, or removed from,
    // the database is actually the value computed
    // by md5(<username>:<realm>:<actual-password>)
  virtual ~UserAuthenticationDatabase();

  virtual void addUserRecord(char const* username, char const* password);
  virtual void removeUserRecord(char const* username);

  virtual char const* lookupPassword(char const* username);
      // returns NULL if the user name was not present

  char const* realm() const { return fRealm; }
  Boolean passwordsAreMD5() const { return fPasswordsAreMD5; }

private:
  mutable std::mutex fTable_mutex; // protects fTable
  HashTable* const fTable;
protected:
  const char *const fRealm;
  const Boolean fPasswordsAreMD5;
};

#endif
