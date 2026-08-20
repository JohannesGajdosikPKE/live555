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
// Copyright (c) 1996-2024 Live Networks, Inc.  All rights reserved.
// A RTSP server
// C++ header

#ifndef _RTSP_SERVER_HH
#define _RTSP_SERVER_HH

#include "GenericMediaServer.hh"
#include "DigestAuthentication.hh"

#include "RTSPCommon.hh"

class RTSPServer;
class RTSPClientSession;
class ServerMediaSubsession;

// The state of a TCP connection used by a RTSP client:
class RTSPClientConnection: public ClientConnection {
public:
  static void create(UsageEnvironment &threaded_env, RTSPServer &ourServer, int clientSocket, struct sockaddr_storage const& clientAddr, Boolean useTLS);
#ifdef IMPLEMENT_REGISTER_COMMAND
  // A data structure that's used to implement the "REGISTER" command:
  class ParamsForREGISTER {
  public:
    ParamsForREGISTER(char const* cmd/*"REGISTER" or "DEREGISTER"*/,
                      RTSPClientConnection& ourConnection, char const* url, char const* urlSuffix,
                      Boolean reuseConnection, Boolean deliverViaTCP, char const* proxyURLSuffix);
    virtual ~ParamsForREGISTER();
    UsageEnvironment &connection_env;
    const ClientConnection::IdType connection_id;
  private:
    friend class RTSPClientConnection;
    char const* fCmd;
    const std::weak_ptr<RTSPClientConnection> fOurConnection;
    char* fURL;
    char* fURLSuffix;
    Boolean fReuseConnection, fDeliverViaTCP;
    char* fProxyURLSuffix;
  };
#endif
  void pretendClientHasClosed(void);
protected: // redefined virtual functions:
  virtual void handleRequestBytes(int newBytesRead);
private:
  void handleRequestBytesBody(void);
  void handleRequestBytesEndOfLoop(Boolean playAfterSetup,std::shared_ptr<RTSPClientSession> &&clientSession,
                                   const char *urlPreSuffix,const char *urlSuffix);
  void handleRequestBytesFinish(void);
  void handleRequestBytesResume(void);
  int newBytesRead,numBytesRemaining;
  unsigned contentLength;
public:
  RTSPClientConnection(UsageEnvironment& threaded_env, RTSPServer& ourServer,
                       int clientSocket, struct sockaddr_storage const& clientAddr,
                       Boolean useTLS = False);
  virtual ~RTSPClientConnection();
protected:
  friend class RTSPClientSession;
    // Make the handler functions for each command virtual, to allow subclasses to reimplement them, if necessary:
  virtual void handleCmd_OPTIONS();
      // You probably won't need to subclass/reimplement this function; reimplement "RTSPServer::allowedCommandNames()" instead.
  virtual void handleCmd_GET_PARAMETER(char const* fullRequestStr); // when operating on the entire server
  virtual void handleCmd_SET_PARAMETER(char const* fullRequestStr); // when operating on the entire server
  virtual void handleCmd_DESCRIBE(char const* urlPreSuffix, char const* urlSuffix, char const* fullRequestStr);
  virtual void handleCmd_DESCRIBE_afterLookup(const std::shared_ptr<ServerMediaSession> &session);
#ifdef IMPLEMENT_REGISTER_COMMAND
  virtual void handleCmd_REGISTER(char const* cmd/*"REGISTER" or "DEREGISTER"*/,
                                  char const* url, char const* urlSuffix, char const* fullRequestStr,
                                  Boolean reuseConnection, Boolean deliverViaTCP, char const* proxyURLSuffix);
        // You probably won't need to subclass/reimplement this function;
        //     reimplement "RTSPServer::weImplementREGISTER()" and "RTSPServer::implementCmd_REGISTER()" instead.
#endif
  virtual void handleCmd_bad();
  virtual void handleCmd_notSupported();
  virtual void handleCmd_redirect(char const* urlSuffix);
  virtual void handleCmd_notFound();
  virtual void handleCmd_sessionNotFound();
  virtual void handleCmd_unsupportedTransport();
    // Support for optional RTSP-over-HTTP tunneling:
  virtual Boolean parseHTTPRequestString(char* resultCmdName, unsigned resultCmdNameMaxSize,
                                         char* urlSuffix, unsigned urlSuffixMaxSize,
                                         char* sessionCookie, unsigned sessionCookieMaxSize,
                                         char* acceptStr, unsigned acceptStrMaxSize);
  virtual void handleHTTPCmd_notSupported();
  virtual void handleHTTPCmd_notFound();
  virtual void handleHTTPCmd_OPTIONS();
  virtual void handleHTTPCmd_TunnelingGET(char const* sessionCookie);
  virtual Boolean handleHTTPCmd_TunnelingPOST(char const* sessionCookie, unsigned char const* extraData, unsigned extraDataSize);
  virtual void handleHTTPCmd_StreamingGET(char const* urlSuffix, char const* fullRequestStr);
protected:
  void resetRequestBuffer();
  void closeSocketsRTSP();
  void handleAlternativeRequestByte1(u_int8_t requestByte);
  Boolean authenticationOK(char const* cmdName, char const* urlSuffix, char const* fullRequestStr);
  void changeClientInputSocket(int newSocketNum, ServerTLSState* newTLSState,
                               unsigned char const* extraData, unsigned extraDataSize);
    // used to implement RTSP-over-HTTP tunneling
#ifdef IMPLEMENT_REGISTER_COMMAND
  static void continueHandlingREGISTER(ParamsForREGISTER* params);
  virtual void continueHandlingREGISTER1(ParamsForREGISTER* params);
#endif
    // Shortcuts for setting up a RTSP response (prior to sending it):
  void setRTSPResponse(char const* responseStr);
  void setRTSPResponse(char const* responseStr, u_int32_t sessionId);
  void setRTSPResponse(char const* responseStr, char const* contentStr);
  void setRTSPResponse(char const* responseStr, u_int32_t sessionId, char const* contentStr);

  RTSPServer &getOurRTSPServer(void);
  const RTSPServer &getOurRTSPServer(void) const;
  void clearClientInputSocket(void) {fOurSocket = -1;}
  void setClientInputSocket(int s) {fOurSocket = s;}
  int getClientInputSocket(void) const {return fOurSocket;}
  void clearClientOutputSocket(void) {fClientOutputSocket = -1;}
  int getClientOutputSocket(void) const {return fClientOutputSocket;}
  int fClientOutputSocket;
  ServerTLSState fPOSTSocketTLS; // used only for RTSP-over-HTTPS
  ServerTLSState* fOutputTLS; // may point to fTLS or fPOSTSocketTLS
  int fAddressFamily;
  Boolean fIsActive;
  unsigned char* fLastCRLF;
  unsigned fRecursionCount;
  char fCurrentCSeq[RTSP_PARAM_STRING_MAX];
  Authenticator fCurrentAuthenticator; // used if access control is needed
  char* fOurSessionCookie; // used for optional RTSP-over-HTTP tunneling
  unsigned fBase64RemainderCount; // used for optional RTSP-over-HTTP tunneling (possible values: 0,1,2,3)
#ifdef IMPLEMENT_REGISTER_COMMAND
  unsigned fScheduledDelayedTask;
#endif
};

// The state of an individual client session (using one or more sequential TCP connections) handled by a RTSP server:
class RTSPClientSession : public ClientSession {
public:
  RTSPClientSession(UsageEnvironment& env, RTSPServer& ourServer, u_int32_t sessionId);
  virtual ~RTSPClientSession();
  virtual void informClientConnect(void) {}
    // informClientDisconnect not needed: this is done in ~RTSPClientSession
  std::shared_ptr<RTSPClientConnection> getOurClientConnection(void) const {return fOurClientConnection.lock();}
public:
    // Make the handler functions for each command virtual, to allow subclasses to redefine them:
  virtual void handleCmd_SETUP(RTSPClientConnection &ourClientConnection,
                               char const* urlPreSuffix, char const* urlSuffix, char const* fullRequestStr);
protected:
  virtual void handleCmd_SETUP_afterLookup1(const std::shared_ptr<ServerMediaSession> &sms);
  virtual void handleCmd_SETUP_afterLookup2(const std::shared_ptr<ServerMediaSession> &sms);
public:
  virtual void handleCmd_withinSession(RTSPClientConnection &ourClientConnection,
                                       char const* cmdName,
                                       char const* urlPreSuffix, char const* urlSuffix,
                                       char const* fullRequestStr);
protected:
  virtual void handleCmd_TEARDOWN(RTSPClientConnection &ourClientConnection,
                                  ServerMediaSubsession* subsession);
  virtual void handleCmd_PLAY(RTSPClientConnection &ourClientConnection,
                              ServerMediaSubsession* subsession, char const* fullRequestStr);
  virtual void handleCmd_PAUSE(RTSPClientConnection &ourClientConnection,
                               ServerMediaSubsession* subsession);
  virtual void handleCmd_GET_PARAMETER(RTSPClientConnection &ourClientConnection,
                                       ServerMediaSubsession* subsession, char const* fullRequestStr);
  virtual void handleCmd_SET_PARAMETER(RTSPClientConnection &ourClientConnection,
                                       ServerMediaSubsession* subsession, char const* fullRequestStr);
public:
  void deleteStreamByTrack(unsigned trackNum);
  Boolean getStreamAfterSETUP (void) const {return fStreamAfterSETUP;}
  void reclaimStreamStates();
  Boolean isMulticast() const { return fIsMulticast; }
protected:

  RTSPServer &getOurRTSPServer(void);
  const RTSPServer &getOurRTSPServer(void) const;
  Boolean fIsMulticast, fStreamAfterSETUP;
  unsigned char fTCPStreamIdCount; // used for (optional) RTP/TCP
  Boolean usesTCPTransport() const { return fTCPStreamIdCount > 0; }
  unsigned fNumStreamStates;
  struct streamState {
    ServerMediaSubsession* subsession;
    int tcpSocketNum;
    void* streamToken;
  } * fStreamStates;

    // Member variables used to implement "handleCmd_SETUP()":
  std::weak_ptr<RTSPClientConnection> fOurClientConnection;
  char const* fURLPreSuffix; char const* fURLSuffix; char const* fFullRequestStr; char const* fTrackId;
};

class RTSPServer: public GenericMediaServer {
public:
#ifdef IMPLEMENT_REGISTER_COMMAND
  typedef void (responseHandlerForREGISTER)(RTSPServer* rtspServer, unsigned requestId, int resultCode, char* resultString);
  unsigned registerStream(const std::shared_ptr<ServerMediaSession> &serverMediaSession,
			  char const* remoteClientNameOrAddress, portNumBits remoteClientPortNum,
			  responseHandlerForREGISTER* responseHandler,
			  char const* username = NULL, char const* password = NULL,
			  Boolean receiveOurStreamViaTCP = False,
			  char const* proxyURLSuffix = NULL);
  // 'Register' the stream represented by "serverMediaSession" with the given remote client (specifed by name and port number).
  // This is done using our custom "REGISTER" RTSP command.
  // The function returns a unique number that can be used to identify the request; this number is also passed to "responseHandler".
  // When a response is received from the remote client (or the "REGISTER" request fails), the specified response handler
  //   (if non-NULL) is called.  (Note that the "resultString" passed to the handler was dynamically allocated,
  //   and should be delete[]d by the handler after use.)
  // If "receiveOurStreamViaTCP" is True, then we're requesting that the remote client access our stream using RTP/RTCP-over-TCP.
  //   (Otherwise, the remote client may choose regular RTP/RTCP-over-UDP streaming.)
  // "proxyURLSuffix" (optional) is used only when the remote client is also a proxy server.
  //   It tells the proxy server the suffix that it should use in its "rtsp://" URL (when front-end clients access the stream)

  typedef void (responseHandlerForDEREGISTER)(RTSPServer* rtspServer, unsigned requestId, int resultCode, char* resultString);
  unsigned deregisterStream(const std::shared_ptr<ServerMediaSession> &serverMediaSession,
			    char const* remoteClientNameOrAddress, portNumBits remoteClientPortNum,
			    responseHandlerForDEREGISTER* responseHandler,
			    char const* username = NULL, char const* password = NULL,
			    char const* proxyURLSuffix = NULL);
  // Used to turn off a previous "registerStream()" - using our custom "DEREGISTER" RTSP command.
#endif
  
  char* rtspURL(ServerMediaSession const* serverMediaSession,
		int clientSocket = -1, Boolean useIPv6 = False) const;
      // returns a "rtsp://" URL that could be used to access the
      // specified session (which must already have been added to
      // us using "addServerMediaSession()".
      // This string is dynamically allocated; caller should delete[]
      // (If "clientSocket" is non-negative, then it is used (by calling "getsockname()") to determine
      //  the IP address to be used in the URL.)
  // Shortcuts:
  char* ipv4rtspURL(ServerMediaSession const* serverMediaSession, int clientSocket = -1) {
    return rtspURL(serverMediaSession, clientSocket, False);
  }
  char* ipv6rtspURL(ServerMediaSession const* serverMediaSession, int clientSocket = -1) {
    return rtspURL(serverMediaSession, clientSocket, True);
  }

  char* rtspURLPrefix(int clientSocket = -1, Boolean useIPv6 = False) const;
      // like "rtspURL()", except that it returns just the common prefix used by
      // each session's "rtsp://" URL.
      // This string is dynamically allocated; caller should delete[]
  // Shortcuts:
  char* ipv4rtspURLPrefix(int clientSocket = -1) { return rtspURLPrefix(clientSocket, False); }
  char* ipv6rtspURLPrefix(int clientSocket = -1) { return rtspURLPrefix(clientSocket, True); }

  UserAuthenticationDatabase* setAuthenticationDatabase(UserAuthenticationDatabase* newDB);
      // Changes the server's authentication database to "newDB", returning a pointer to the old database (if there was one).
      // "newDB" may be NULL (you can use this to disable authentication at runtime, if desired).

  void disableStreamingRTPOverTCP() {
    fAllowStreamingRTPOverTCP = False;
  }

  Boolean setUpTunnelingOverHTTP(Port httpPort);
      // (Attempts to) enable RTSP-over-HTTP tunneling on the specified port.
      // Returns True iff the specified port can be used in this way (i.e., it's not already being used for a separate HTTP server).
      // Note: RTSP-over-HTTP tunneling is described in
      //  http://mirror.informatimago.com/next/developer.apple.com/quicktime/icefloe/dispatch028.html
      //  and http://images.apple.com/br/quicktime/pdf/QTSS_Modules.pdf
  portNumBits httpServerPortNum() const; // in host byte order.  (Returns 0 if not present.)

  void setTLSState(char const* certFileName, char const* privKeyFileName,
		   Boolean weServeSRTP = True, Boolean weEncryptSRTP = True);

protected:
  RTSPServer(UsageEnvironment& env,
	     int ourSocketIPv4, int ourSocketIPv6, Port ourPort,
	     UserAuthenticationDatabase* authDatabase,
	     unsigned reclamationSeconds);
      // called only by createNew();
  virtual ~RTSPServer();

  virtual char const* allowedCommandNames(); // used to implement "RTSPClientConnection::handleCmd_OPTIONS()"
#ifdef IMPLEMENT_REGISTER_COMMAND
  virtual Boolean weImplementREGISTER(UsageEnvironment& env, char const* cmd/*"REGISTER" or "DEREGISTER"*/,
				      char const* proxyURLSuffix, char*& responseStr);
      // used to implement "RTSPClientConnection::handleCmd_REGISTER()"
      // Note: "responseStr" is dynamically allocated (or NULL), and should be delete[]d after the call
  virtual void implementCmd_REGISTER(UsageEnvironment& env, char const* cmd/*"REGISTER" or "DEREGISTER"*/,
				     char const* url, char const* urlSuffix, int socketToRemoteServer,
				     Boolean deliverViaTCP, char const* proxyURLSuffix);
      // used to implement "RTSPClientConnection::handleCmd_REGISTER()"
#endif
  virtual UserAuthenticationDatabase* getAuthenticationDatabaseForCommand(char const* cmdName);
  virtual Boolean specialClientAccessCheck(int clientSocket,
					   struct sockaddr_storage const& clientAddr,
					   char const* urlSuffix);
      // a hook that allows subclassed servers to do server-specific access checking
      // on each client (e.g., based on client IP address), without using digest authentication.
  virtual Boolean specialClientUserAccessCheck(int clientSocket,
					       struct sockaddr_storage const& clientAddr,
					       char const* urlSuffix, char const *username);
      // another hook that allows subclassed servers to do server-specific access checking
      // - this time after normal digest authentication has already taken place (and would otherwise allow access).
      // (This test can only be used to further restrict access, not to grant additional access.)
  virtual void specialHandlingOfAuthenticationFailure(int clientSocket,
						      struct sockaddr_storage const& clientAddr,
						      char const* urlSuffix);
      // a hook that allows subclassed servers to take extra action whenevever an authentication failure occurs

public: // redefined virtual functions
  virtual Boolean isRTSPServer() const;
  virtual void addServerMediaSession(const std::shared_ptr<ServerMediaSession> &serverMediaSession);

protected: // redefined virtual functions
  // If you subclass "RTSPClientConnection", then you must also redefine this virtual function in order
  // to create new objects of your subclass:
  void createNewClientConnectionImpl(UsageEnvironment& env, int clientSocket, struct sockaddr_storage const& clientAddr) override;

protected:
  // If you subclass "RTSPClientSession", then you must also redefine this virtual function in order
  // to create new objects of your subclass:
  std::shared_ptr<ClientSession> createNewClientSession(UsageEnvironment& env, u_int32_t sessionId) override;

private:
  static void incomingConnectionHandlerHTTPIPv4(void*, int /*mask*/);
  void incomingConnectionHandlerHTTPIPv4();
  static void incomingConnectionHandlerHTTPIPv6(void*, int /*mask*/);
  void incomingConnectionHandlerHTTPIPv6();

  void noteTCPStreamingOnSocket(int socketNum, u_int32_t clientSessionId, unsigned trackNum);
  void unnoteTCPStreamingOnSocket(int socketNum, u_int32_t clientSessionId, unsigned trackNum);
  void stopTCPStreamingOnSocket(int socketNum);

private:
  friend class RTSPClientConnection;
  friend class RTSPClientSession;
  friend class RegisterRequestRecord;
  friend class DeregisterRequestRecord;
  int fHTTPServerSocketIPv4, fHTTPServerSocketIPv6; // for optional RTSP-over-HTTP tunneling
  Port fHTTPServerPort; // ditto
  std::map<std::string, std::weak_ptr<RTSPClientConnection> > fClientConnectionsForHTTPTunneling; // maps client-supplied 'session cookie' strings to "RTSPClientConnection"s
  std::mutex fClientConnectionsForHTTPTunneling_mutex;
    // (used only for optional RTSP-over-HTTP tunneling)
  HashTable* fTCPStreamingDatabase;
  mutable std::recursive_mutex fTCPStreamingDatabase_mutex; // protectes fTCPStreamingDatabase only
    // maps TCP socket numbers to ids of sessions that are streaming over it (RTP/RTCP-over-TCP)
#ifdef IMPLEMENT_REGISTER_COMMAND
  HashTable* fPendingRegisterOrDeregisterRequests;
  unsigned fRegisterOrDeregisterRequestCounter;
#endif
  UserAuthenticationDatabase* fAuthDB;
  Boolean fAllowStreamingRTPOverTCP; // by default, True
  Boolean fOurConnectionsUseTLS; // by default, False
  Boolean fWeServeSRTP; // used only if "fOurConnectionsUseTLS" is True
  Boolean fWeEncryptSRTP; // used only if "fWeServeSRTP" is True
  mutable std::recursive_mutex internal_mutex;
};


#ifdef IMPLEMENT_REGISTER_COMMAND
////////// A subclass of "RTSPServer" that implements the "REGISTER" command to set up proxying on the specified URL //////////

class RTSPServerWithREGISTERProxying: public RTSPServer {
public:
  static RTSPServerWithREGISTERProxying* createNew(UsageEnvironment& env, Port ourPort = 554,
						   UserAuthenticationDatabase* authDatabase = NULL,
						   UserAuthenticationDatabase* authDatabaseForREGISTER = NULL,
						   unsigned reclamationSeconds = 65,
						   Boolean streamRTPOverTCP = False,
						   int verbosityLevelForProxying = 0,
						   char const* backEndUsername = NULL,
						   char const* backEndPassword = NULL);

protected:
  RTSPServerWithREGISTERProxying(UsageEnvironment& env, int ourSocketIPv4, int ourSocketIPv6, Port ourPort,
				 UserAuthenticationDatabase* authDatabase, UserAuthenticationDatabase* authDatabaseForREGISTER,
				 unsigned reclamationSeconds,
				 Boolean streamRTPOverTCP, int verbosityLevelForProxying,
				 char const* backEndUsername, char const* backEndPassword);
  // called only by createNew();
  virtual ~RTSPServerWithREGISTERProxying();

protected: // redefined virtual functions
  virtual char const* allowedCommandNames();
  virtual Boolean weImplementREGISTER(UsageEnvironment &env, char const* cmd/*"REGISTER" or "DEREGISTER"*/,
				      char const* proxyURLSuffix, char*& responseStr);
  virtual void implementCmd_REGISTER(UsageEnvironment& env, char const* cmd/*"REGISTER" or "DEREGISTER"*/,
				     char const* url, char const* urlSuffix, int socketToRemoteServer,
				     Boolean deliverViaTCP, char const* proxyURLSuffix);
  virtual UserAuthenticationDatabase* getAuthenticationDatabaseForCommand(char const* cmdName);

private:
  Boolean fStreamRTPOverTCP;
  int fVerbosityLevelForProxying;
  unsigned fRegisteredProxyCounter;
  char* fAllowedCommandNames;
  UserAuthenticationDatabase* fAuthDBForREGISTER;
  char* fBackEndUsername;
  char* fBackEndPassword;
}; 
#endif

inline RTSPServer &RTSPClientConnection::getOurRTSPServer(void) {
  return static_cast<RTSPServer&>(fOurServer);
}

inline const RTSPServer &RTSPClientConnection::getOurRTSPServer(void) const {
  return static_cast<const RTSPServer&>(fOurServer);
}

inline RTSPServer &RTSPClientSession::getOurRTSPServer(void) {
  return static_cast<RTSPServer&>(fOurServer);
}

inline const RTSPServer &RTSPClientSession::getOurRTSPServer(void) const {
  return static_cast<const RTSPServer&>(fOurServer);
}


#ifdef IMPLEMENT_REGISTER_COMMAND
// A special version of "parseTransportHeader()", used just for parsing the "Transport:" header
// in an incoming "REGISTER" command:
void parseTransportHeaderForREGISTER(char const* buf, // in
				     Boolean &reuseConnection, // out
				     Boolean& deliverViaTCP, // out
				     char*& proxyURLSuffix); // out
#endif

#endif
