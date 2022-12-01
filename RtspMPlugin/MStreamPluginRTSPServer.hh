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

#ifndef _MEDIA_SERVER_PLUGIN_RTSP_SERVER_HH
#define _MEDIA_SERVER_PLUGIN_RTSP_SERVER_HH

#include "RTSPServer.hh"
#include "IMStream.h"

#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <iostream>

class MediaServerPluginRTSPServer : public RTSPServer {
public:
  enum ServerType {
    type_rtsp_and_http = 0,
    type_rtsps_only = 1,
    type_https_only = 2
  };
  static const char *ServerTypeToString(int t);
  static MediaServerPluginRTSPServer *createNew(ServerType type,bool &success,
                                                UsageEnvironment &env,
                                                const RTSPParameters &params,
                                                IMStreamFactory *streamManager);
  class StreamMapEntry;
  bool destructorStarted(void) const {return destructor_started;}

  void printPortInfo(std::ostream &o) const;
  typedef std::map<std::string,std::multiset<std::string> > InfoMap;
  typedef std::map<std::string,std::set<std::string> > SubsessionMap;
  void generateConnectionStreamInfo(InfoMap &connection_info,InfoMap &stream_info,
                                    SubsessionMap &subsessions) const;
protected:
  MediaServerPluginRTSPServer(ServerType type,UsageEnvironment &env, int ourSocketIPv4, int ourSocketIPv6,
                              int m_HTTPServerSocketIPv4, int m_HTTPServerSocketIPv6,
                              const RTSPParameters &params, IMStreamFactory* streamManager);
  // called only by createNew();
  ~MediaServerPluginRTSPServer(void) override;

protected:
  struct LookupCompletionFuncData;
  static void GetStreamCb(void *cb_context,
                          const std::shared_ptr<IMStream> &stream);
  void getStreamCb(const LookupCompletionFuncData *l,
                   const std::shared_ptr<IMStream> &stream);
  void lookupServerMediaSession(UsageEnvironment &env, char const *streamName,
                                lookupServerMediaSessionCompletionFunc *completionFunc,
                                void *completionClientData,
                                Boolean isFirstLookupInSession = True) override;
  ServerMediaSession *createServerMediaSession(UsageEnvironment &env,
                                               const std::shared_ptr<StreamMapEntry> &e);

  static void IncomingConnectionHandlerHTTPIPv4(void* instance, int /*mask*/);
  void incomingConnectionHandlerHTTPIPv4(void);
  static void IncomingConnectionHandlerHTTPIPv6(void* instance, int /*mask*/);
  void incomingConnectionHandlerHTTPIPv6(void);

  class MyRTSPClientSession;
  ClientSession *createNewClientSession(UsageEnvironment &env, u_int32_t sessionId) override;

  UsageEnvironment *createNewUsageEnvironment(TaskScheduler &scheduler) override;
  std::shared_ptr<StreamMapEntry> getStreamMapEntry(const std::string &stream_name) const;

  const ServerType type;
  int m_HTTPServerSocketIPv4,m_HTTPServerSocketIPv6;
  const RTSPParameters params;
  IMStreamFactory *const stream_factory;
  std::map<std::string,std::weak_ptr<StreamMapEntry> > stream_map;
  mutable std::recursive_mutex stream_map_mutex;
  const std::unique_ptr<const char[]> m_urlPrefix;
  bool destructor_started = false;
};

#endif
