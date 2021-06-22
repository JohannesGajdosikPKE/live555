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
// Copyright (c) 1996-2021, Live Networks, Inc.  All rights reserved
// A subclass of "RTSPServer" that creates "ServerMediaSession"s on demand,
// based on whether or not the specified stream name exists as a file
// Header file

#ifndef _DYNAMIC_RTSP_SERVER_HH
#define _DYNAMIC_RTSP_SERVER_HH

#include "RTSPServer.hh"
#include "IRTC.h"
#include "SSLSocketServerPipe.h"

#include <map>
#include <memory>
#include <mutex>

class MediaServerPluginRTSPServer : public RTSPServer {
public:
  static MediaServerPluginRTSPServer *createNew(UsageEnvironment &env,
                                                const RTSPParameters &params,
                                                IRTCStreamFactory *streamManager);
  class StreamMapEntry;
protected:
  MediaServerPluginRTSPServer(UsageEnvironment &env, int ourSocketIPv4, int ourSocketIPv6,
                              const RTSPParameters &params, IRTCStreamFactory* streamManager);
  // called only by createNew();
  ~MediaServerPluginRTSPServer() override;

protected:
  struct LookupCompletionFuncData;
  static void GetStreamCb(void *cb_context,
                          const TStreamPtr &stream);
  void getStreamCb(const LookupCompletionFuncData *l,
                   const TStreamPtr &stream);
  void lookupServerMediaSession(UsageEnvironment &env, char const *streamName,
                                lookupServerMediaSessionCompletionFunc *completionFunc,
                                void *completionClientData,
                                Boolean isFirstLookupInSession = True) override;
  ServerMediaSession *createServerMediaSession(UsageEnvironment &env,
                                               const char *stream_name,
                                               const std::shared_ptr<StreamMapEntry> &e);

  static void incomingConnectionHandlerHTTPoverSSL(void* instance, int /*mask*/);
  void incomingConnectionHandlerHTTPoverSSL(void);
  static void incomingConnectionHandlerHTTP(void* instance, int /*mask*/);
  void incomingConnectionHandlerHTTP(void);

  class RTSPClientConnectionSSL : public RTSPServer::RTSPClientConnection, public SSLSocketServerPipe
  {
    RTSPClientConnectionSSL(UsageEnvironment &env, RTSPServer& ourServer, int clientSocket, struct sockaddr_storage clientAddr, const char* certpath, const char* keypath);
  public:
    static RTSPClientConnectionSSL *create(UsageEnvironment& env, MediaServerPluginRTSPServer& ourServer, int clientSocket, struct sockaddr_storage clientAddr, const char* certpath, const char* keypath);
    virtual ~RTSPClientConnectionSSL();
  };

  ClientConnection *createNewClientConnectionSSL(int clientSocket, struct sockaddr_storage clientAddr,
                                                 const char* certpath, const char* keypath);

  int m_HTTPServerSocket,m_HTTPsServerSocket;
  const RTSPParameters params;
  IRTCStreamFactory *const streamManager;
  std::map<std::string,std::shared_ptr<StreamMapEntry> > stream_map;
  mutable std::recursive_mutex stream_map_mutex;
};

#endif
