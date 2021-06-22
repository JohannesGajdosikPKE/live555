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
// Implementation

#include "MediaServerPluginRTSPServer.hh"
#include "H264VideoStreamDiscreteFramer.hh"
#include "BasicUsageEnvironment.hh"
#include "IRTC.h"
#include <liveMedia.hh>
#include <Base64.hh>
#include <GroupsockHelper.hh>

#include <string.h>

#include <iostream>
#include <iomanip>

struct Frame {
  Frame(void) : size(0), time(0) {}
  Frame(const uint8_t *data,int32_t size,int64_t time)
   : size((data && size>0)?size:0), time(time), data(new uint8_t[Frame::size]) {
    if (Frame::size) memcpy(const_cast<uint8_t*>(Frame::data.get()),data,Frame::size);
  }
  const int32_t size;
  const int64_t time;
  const std::shared_ptr<const uint8_t[]> data;
};

static void PrintBytes(const uint8_t *data, int size, int64_t time) {
  std::cout << time << ':' << std::setw(5) << size << std::hex;
  for (int i=0;i<32 && i < size;i++) std::cout << ' ' << std::setw(2) << std::setfill('0') << (uint32_t)(data[i]);
  std::cout << std::dec << std::endl;
}


class MediaServerPluginRTSPServer::StreamMapEntry : public std::enable_shared_from_this<MediaServerPluginRTSPServer::StreamMapEntry> {
public:
  StreamMapEntry(const TStreamPtr &stream,std::function<void(void)> &&on_close)
      : stream(stream),on_close(std::move(on_close)) {
      // RegisterOnClose might call OnClose early, so lock the mutex:
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    subsession_info_list = stream->getSubsessionInfoList();
    stream->RegisterOnClose(this,&StreamMapEntry::OnClose);
  }
  ~StreamMapEntry(void) {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    registration_map.clear();
    stream->DeregisterOnClose(this);
    stream.reset();
      // defensive programming: in case of programming error segfault as early as possible:
    subsession_info_list = nullptr;
  }
  const SubsessionInfo *const *getSubsessionInfoList(void) const {return subsession_info_list;}
  typedef std::function<void(const Frame&)> FrameFunction;
  class RegistrationEntry;
  class Registration {
  public:
      // in fact I want to make the constructor private with
      // friend std::shared_ptr<Registration> StreamMapEntry::connect(const SubsessionInfo *info,FrameFunction &&f);
      // but this does not work out. When anyone finds out how to do this, please fix.
      // Until then: do not call this constructor, only connect() may call it.
    Registration(const std::shared_ptr<StreamMapEntry> &map_entry,const SubsessionInfo *info)
      : map_entry(map_entry),info(info) {}
  public:
    ~Registration(void) {disconnect();}
    void disconnect(void) {
      std::shared_ptr<StreamMapEntry> e(map_entry.lock());
      if (e) e->disconnect(info,this); // will reset the map_entry
    }
  private:
    friend class RegistrationEntry;
    std::weak_ptr<StreamMapEntry> map_entry;
    const SubsessionInfo *const info;
  };
  std::shared_ptr<Registration> connect(const SubsessionInfo *info,FrameFunction &&f) {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    auto &r(registration_map[info]);
    r.registration_mutex = &registration_mutex;
    const bool first_entry = r.empty();
    std::shared_ptr<Registration> reg(std::make_shared<Registration>(shared_from_this(),info));
    r[reg.get()] = std::move(f);
    if (first_entry) {
      stream->RegisterOnFrame(&r,info,
                              (info->GetFormat() == RTCFormatH264)
                                ? &StreamMapEntry::OnH264FrameCallback
                                : &StreamMapEntry::OnFrameCallback);
    }
    return reg;
  }
private:
  std::shared_ptr<IRTCStream> stream;
  const std::function<void(void)> on_close;
  static void OnClose(void *context) {reinterpret_cast<StreamMapEntry*>(context)->onClose();}
  void onClose(void) {
      // called from the executables threads:
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    registration_map.clear();
    stream.reset();
    subsession_info_list = nullptr;
    if (on_close) on_close();
  }
  friend class Registration;
  void disconnect(const SubsessionInfo *info,Registration *reg) {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    auto it(registration_map.find(info));
    if (it == registration_map.end()) abort();
      // will call the destructor of the RegistrationEntry wich in turn
      // will invalidate the registration and all the FrameCb with an emty Frame
    if (it->second.erase(reg) != 1) abort();
    if (it->second.empty()) {
      stream->DeregisterOnFrame(&it->second,info);
    }
  }
private:
  static void OnH264NalCallback(void *callerId, const uint8_t *buffer, int bufferSize, const int64_t &frameTime) {
/*
      maybe this code will be useful later
    FrameFunctionMap &r(*reinterpret_cast<FrameFunctionMap*>(callerId));
    const uint8_t nal_unit_type = (*buffer & 0x1f);
    if (nal_unit_type == 7) {
      if (bufferSize >= 4) {
        r.setH264ProfileLevelId(
            (((uint32_t)buffer[1])<<16)|(((uint32_t)buffer[2])<<8)|((uint32_t)buffer[3]));
      }
      r.setH264Sps64(std::shared_ptr<const char[]>(base64Encode((const char*)buffer,bufferSize)));
    } else if (nal_unit_type == 8) {
      r.setH264Pps64(std::shared_ptr<const char[]>(base64Encode((const char*)buffer,bufferSize)));
    }
*/
    OnFrameCallback(callerId,buffer,bufferSize,frameTime);
  }
  static void OnH264FrameCallback(void *callerId, const uint8_t *buffer, int bufferSize, const int64_t &frameTime) {
    if (bufferSize <= 0) return;
      // extract all nal units, strip h264 bytestream headers:
    const uint8_t *p = buffer;
    const uint8_t *const end = buffer+bufferSize;
    const uint8_t *const end3 = end - 3;
    for (;;) {
      const uint8_t *p0 = p;
      for (;p0<end3;p0++) {
        if (p0[0]==0 && p0[1]==0 && p0[2]==1) {
          goto nal_start_found;
        }
      }
        // no more 001 until the end:
      OnH264NalCallback(callerId,p,end-p,frameTime);
      break;
      nal_start_found:
      const uint8_t *p_next = p0 + 3;
      if (p0 > p) {
        if (p0[-1]==0) p0--;
        if (p0 > p) OnH264NalCallback(callerId,p,p0-p,frameTime);
      }
      p = p_next;
    }
  }
  static void OnFrameCallback(void *callerId, const uint8_t *buffer, int bufferSize, const int64_t &frameTime) {
    const Frame f(buffer,bufferSize,frameTime);
    FrameFunctionMap &r(*reinterpret_cast<FrameFunctionMap*>(callerId));
    std::lock_guard<std::recursive_mutex> lock(*r.registration_mutex);
    for (auto &it : r) it.second(f);
  }
  mutable std::recursive_mutex registration_mutex;
  class RegistrationEntry {
    RegistrationEntry(void) {}
    RegistrationEntry(FrameFunction &&func,const std::shared_ptr<Registration> &reg)
      : func(std::move(func)),reg(reg) {}
    ~RegistrationEntry(void) {
        // registration_mutex is already locked
      const std::shared_ptr<Registration> r(reg.lock());
      if (r) {
        static const Frame empty_frame;
        func(empty_frame);
        r->map_entry.reset();
      }
    }
    FrameFunction func;
    std::weak_ptr<Registration> reg;
  };
  struct FrameFunctionMap : public std::map<Registration*,FrameFunction> {
    FrameFunctionMap(void) : h264_profile_level_id(0) {}
    std::recursive_mutex *registration_mutex = nullptr;
    void setH264ProfileLevelId(unsigned int x) {h264_profile_level_id = x;}
    void setH264Sps64(const std::shared_ptr<const char[]> &x) {h264_sps64 = x;}
    void setH264Pps64(const std::shared_ptr<const char[]> &x) {h264_pps64 = x;}
    unsigned int h264_profile_level_id;
    std::shared_ptr<const char[]> h264_sps64,h264_pps64;
  };
  std::map<const SubsessionInfo*,FrameFunctionMap> registration_map;
  const SubsessionInfo *const *subsession_info_list;
};





static
int CreateAcceptSocket(UsageEnvironment& env, Port ourPort, unsigned int bind_to_interface) {
  int accept_fd = ::socket(AF_INET,SOCK_STREAM,0);
  if (accept_fd < 0) {
    env.setResultErrMsg("socket() failed: ");
    return -1;
  }
  const int yes = -1; // all bits set to 1
  if (0 != ::setsockopt(accept_fd,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char*)(&yes),sizeof(yes))) {
    env.setResultErrMsg("setsockopt(SO_EXCLUSIVEADDRUSE) failed: ");
    ::closeSocket(accept_fd);
    return -1;
  }
  struct sockaddr_in sock_addr;
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.s_addr = htonl(bind_to_interface);
  sock_addr.sin_port = ourPort.num(); // already network order
  if (0 != bind(accept_fd,(struct sockaddr*)(&sock_addr),sizeof(sock_addr))) {
    env.setResultErrMsg("bind() failed: ");
    ::closeSocket(accept_fd);
    return -1;
  }
  if (0 != ::listen(accept_fd,20)) {
    env.setResultErrMsg("listen() failed: ");
    ::closeSocket(accept_fd);
    return -1;
  }
  return accept_fd;
}



MediaServerPluginRTSPServer*
MediaServerPluginRTSPServer::createNew(UsageEnvironment &env, const RTSPParameters &params, IRTCStreamFactory* streamManager) {
  int ourSocketIPv4 = CreateAcceptSocket(env, Port(params.port), params.bind_to_interface);
  int ourSocketIPv6 = setUpOurSocket(env, Port(params.port), AF_INET6);
  if (ourSocketIPv4 < 0 && ourSocketIPv6 < 0) return NULL;

  return new MediaServerPluginRTSPServer(env, ourSocketIPv4, ourSocketIPv6, params, streamManager);
}

MediaServerPluginRTSPServer::MediaServerPluginRTSPServer(UsageEnvironment &env, int ourSocketIPv4, int ourSocketIPv6,
                                                         const RTSPParameters &params, IRTCStreamFactory *streamManager)
                            :RTSPServer(env, ourSocketIPv4, ourSocketIPv6, Port(params.port), NULL, 65),
                             params(params), streamManager(streamManager) {
  if (params.httpPort) {
    m_HTTPServerSocket = CreateAcceptSocket(env, params.httpPort, params.bind_to_interface);
envir() << "MediaServerPluginRTSPServer::MediaServerPluginRTSPServer: CreateAcceptSocket(" << params.httpPort << ") returned "
        << m_HTTPServerSocket << "\n";
    if (m_HTTPServerSocket >= 0) {
      env.taskScheduler().turnOnBackgroundReadHandling(m_HTTPServerSocket,
        incomingConnectionHandlerHTTP, this);
    }
  }
  if (params.httpsPort) {
    m_HTTPsServerSocket = CreateAcceptSocket(env, params.httpsPort, params.bind_to_interface);
envir() << "MediaServerPluginRTSPServer::MediaServerPluginRTSPServer: CreateAcceptSocket(" << params.httpsPort << ") returned "
        << m_HTTPsServerSocket << "\n";
    if (m_HTTPsServerSocket >= 0) {
      env.taskScheduler().turnOnBackgroundReadHandling(m_HTTPsServerSocket,
        incomingConnectionHandlerHTTPoverSSL, this);
    }
  }
}

MediaServerPluginRTSPServer::~MediaServerPluginRTSPServer() {
  if (m_HTTPsServerSocket >= 0) {
    envir().taskScheduler().turnOffBackgroundReadHandling(m_HTTPsServerSocket);
    ::closeSocket(m_HTTPsServerSocket);
  }
  if (m_HTTPServerSocket >= 0) {
    envir().taskScheduler().turnOffBackgroundReadHandling(m_HTTPServerSocket);
    ::closeSocket(m_HTTPServerSocket);
  }
  RTSPServer::cleanup();
      // This member function must be called in the destructor of any subclass of
      // "GenericMediaServer".  (We don't call this in the destructor of "GenericMediaServer" itself,
      // because by that time, the subclass destructor will already have been called, and this may
      // affect (break) the destruction of the "ClientSession" and "ClientConnection" objects, which
      // themselves will have been subclassed.)
}

void MediaServerPluginRTSPServer::incomingConnectionHandlerHTTPoverSSL(void* instance, int /*mask*/) {
  MediaServerPluginRTSPServer* server = (MediaServerPluginRTSPServer*)instance;
  server->incomingConnectionHandlerHTTPoverSSL();
}

void MediaServerPluginRTSPServer::incomingConnectionHandlerHTTPoverSSL()
{
  struct sockaddr_storage clientAddr;
  SOCKLEN_T clientAddrLen = sizeof clientAddr;
  int clientSocket = accept(m_HTTPsServerSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
  envir() << "MediaServerPluginRTSPServer::incomingConnectionHandlerHTTPoverSSL: accept(" << m_HTTPsServerSocket << ") returned " << clientSocket << "\n";
  if (clientSocket < 0) {
    int err = envir().getErrno();
    if (err != EWOULDBLOCK) {
      envir().setResultErrMsg("accept() failed: ");
    }
    return;
  }
  ignoreSigPipeOnSocket(clientSocket); // so that clients on the same host that are killed don't also kill us

#ifdef DEBUG
  envir() << "accept()ed connection from " << AddressString(clientAddr).val() << "\n";
#endif

  // Create a new object for handling this connection:
  createNewClientConnectionSSL(clientSocket, clientAddr, params.getHttpCertFile().c_str(),params.getHttpKeyPath().c_str());
}

void MediaServerPluginRTSPServer::incomingConnectionHandlerHTTP(void* instance, int /*mask*/) {
  MediaServerPluginRTSPServer* server = (MediaServerPluginRTSPServer*)instance;
  server->incomingConnectionHandlerHTTP();
}

void MediaServerPluginRTSPServer::incomingConnectionHandlerHTTP() {
  envir() << "MediaServerPluginRTSPServer::incomingConnectionHandlerHTTP: calling incomingConnectionHandlerOnSocket(" << m_HTTPServerSocket << ")\n";
  incomingConnectionHandlerOnSocket(m_HTTPServerSocket);
}


GenericMediaServer::ClientConnection*
MediaServerPluginRTSPServer::createNewClientConnectionSSL(int clientSocket, struct sockaddr_storage clientAddr, const char* certpath, const char* keypath)
{
  return RTSPClientConnectionSSL::create(getBestThreadedUsageEnvironment(), *this, clientSocket, clientAddr, certpath, keypath);
}

MediaServerPluginRTSPServer::RTSPClientConnectionSSL*
MediaServerPluginRTSPServer::RTSPClientConnectionSSL::create(UsageEnvironment& env, MediaServerPluginRTSPServer& ourServer, int clientSocket, struct sockaddr_storage clientAddr,
                                                             const char* certpath, const char* keypath) {
  RTSPClientConnectionSSL *rval = new RTSPClientConnectionSSL(env, ourServer, clientSocket, clientAddr, certpath, keypath);
  GenericMediaServer::Semaphore sem;
  env.taskScheduler().executeCommand([rval,clientSocket,p=ourServer.params.httpPort,certpath,keypath,&sem]() {
    rval->afterConstruction();
    rval->AcceptClientAndConnectPipe(clientSocket, p, certpath, keypath);
    sem.post();
  });
  sem.wait();
env << "MediaServerPluginRTSPServer::RTSPClientConnectionSSL::create(" << &ourServer << "," << clientSocket << ") returns " << rval << "\n";
  return rval;
}

MediaServerPluginRTSPServer::RTSPClientConnectionSSL::RTSPClientConnectionSSL(
      UsageEnvironment &env, RTSPServer& ourServer, int clientSocket, struct sockaddr_storage clientAddr,
      const char* certpath, const char* keypath)
  : RTSPClientConnection(env, ourServer, clientSocket, clientAddr),
    SSLSocketServerPipe(env) {
  envir() << "MediaServerPluginRTSPServer::RTSPClientConnectionSSL::RTSPClientConnectionSSL(" << clientSocket << ")\n";
}

MediaServerPluginRTSPServer::RTSPClientConnectionSSL::~RTSPClientConnectionSSL(void) {
  envir() << "MediaServerPluginRTSPServer::RTSPClientConnectionSSL(" << fOurSocket << ")::~RTSPClientConnectionSSL\n";
}


class MyServerMediaSubsession;

class MyFrameSource : public FramedSource {
public:
  static MyFrameSource *createNew(UsageEnvironment &env,
                                  MediaServerPluginRTSPServer::StreamMapEntry &e,
                                  const SubsessionInfo *info) {
    MyFrameSource *rval = new MyFrameSource(env);
    rval->connect(e,info);
    return rval;
  }
private:
  MyFrameSource(UsageEnvironment &env) : FramedSource(env) {}
  ~MyFrameSource(void) override {}
  void connect(MediaServerPluginRTSPServer::StreamMapEntry &e,
               const SubsessionInfo *info) {
    frame_connection = e.connect(info,
          [this](const Frame &f) {
            envir().taskScheduler().executeCommand(
              [this,f]() {
                my_frame_queue.push(f); // Frame contains shared Ptr to data
                deliverFrame();
              });
          });
  }
  void deliverFrame(void) {
    if (!isCurrentlyAwaitingData()) return; // we're not ready for the data yet
    if (my_frame_queue.empty()) return;
    Frame &f(my_frame_queue.front());
    const u_int8_t *const frame_data = f.data.get();
    const unsigned int frame_size = f.size;
    if (frame_size <= 0) {
      handleClosure(); // teardown
      return;
    }
    if (frame_size > fMaxSize) {
      fFrameSize = fMaxSize;
      fNumTruncatedBytes = frame_size - fMaxSize;
    } else {
      fFrameSize = frame_size;
      fNumTruncatedBytes = 0;
    }
    fPresentationTime.tv_sec  = f.time / 1000000LL;
    fPresentationTime.tv_usec = f.time - 1000000LL*fPresentationTime.tv_sec;
      // If the device is *not* a 'live source'
      // (e.g., it comes instead from a file or buffer),
      // then set "fDurationInMicroseconds" here.
    fDurationInMicroseconds = 0;
    memcpy(fTo,frame_data,fFrameSize);
    my_frame_queue.pop();
    FramedSource::afterGetting(this);
  }
  void doGetNextFrame(void) override {
    deliverFrame();
  }
  std::queue<Frame> my_frame_queue;
  std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry::Registration>  frame_connection;
};


class MyServerMediaSubsession : public OnDemandServerMediaSubsession {
public:
  static MyServerMediaSubsession *createNew(UsageEnvironment &env,
                                            const char *stream_name,
                                            const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                                            const SubsessionInfo *info);
  MyServerMediaSubsession(UsageEnvironment &env,
                          const char *stream_name,
                          const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                          const SubsessionInfo *info)
    : OnDemandServerMediaSubsession(env,True), // reuseFirstSource
      stream_name(stream_name),
      e(e),
      info(info) {
    envir() << "MyServerMediaSubsession::MyServerMediaSubsession(" << stream_name << ")\n";
  }
  ~MyServerMediaSubsession(void) {
    envir() << "MyServerMediaSubsession(" << stream_name.c_str() << ")::~MyServerMediaSubsession\n";
  }
protected:
  MyFrameSource *createFrameSource(unsigned clientSessionId) {
    return MyFrameSource::createNew(envir(),*e,info);
  }
  const std::string stream_name;
  const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> e;
  const SubsessionInfo *info;
};

class MyH264ServerMediaSubsession : public MyServerMediaSubsession {
public:
  MyH264ServerMediaSubsession(UsageEnvironment &env,
                              const char *stream_name,
                              const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                              const SubsessionInfo *info)
    : MyServerMediaSubsession(env,stream_name,e,info) {
  }
protected:
  const char *getAuxSDPLine(RTPSink*,FramedSource*) override {return info->getAuxSdpLine();}
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    estBitrate = info->getEstBitrate(); // kbps, estimate
    H264VideoStreamDiscreteFramer *const rval
      = H264VideoStreamDiscreteFramer::createNew(envir(),createFrameSource(clientSessionId));
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *const rval = H264VideoRTPSink::createNew(envir(),
                                                      rtpGroupsock,
                                                      rtpPayloadTypeIfDynamic);
    return rval;
  }
};

class MyUnknownServerMediaSubsession : public MyServerMediaSubsession {
public:
  MyUnknownServerMediaSubsession(UsageEnvironment &env,
                                 const char *stream_name,
                                 const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                                 const SubsessionInfo *info)
    : MyServerMediaSubsession(env,stream_name,e,info) {
  }
protected:
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    estBitrate = info->getEstBitrate();
    MyFrameSource *const rval = createFrameSource(clientSessionId);
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *const rval
      = SimpleRTPSink::createNew(envir(),
                                 rtpGroupsock,
                                 rtpPayloadTypeIfDynamic,
                                 info->getRtpTimestampFrequency(),
                                 info->getSdpMediaTypeString(),
                                 info->getRtpPayloadFormatName(),
                                 1,False);
    return rval;
  }
};

MyServerMediaSubsession
  *MyServerMediaSubsession::createNew(UsageEnvironment &env,
                                      const char *stream_name,
                                      const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                                      const SubsessionInfo *info) {
  MyServerMediaSubsession *rval = nullptr;
  if (info->GetFormat() == RTCFormatH264) {
    rval = new MyH264ServerMediaSubsession(env,stream_name,e,info);
  } else {
    rval = new MyUnknownServerMediaSubsession(env,stream_name,e,info);
  }
  return rval;
}




struct MediaServerPluginRTSPServer::LookupCompletionFuncData {
  LookupCompletionFuncData(
    MediaServerPluginRTSPServer *self,
    UsageEnvironment &env, char const *streamName,
    lookupServerMediaSessionCompletionFunc *completionFunc,
    void *completionClientData)
      : self(self),env(env),streamName(streamName),
        completionFunc(completionFunc),completionClientData(completionClientData) {}
  MediaServerPluginRTSPServer *self;
  UsageEnvironment &env;
  const std::string streamName;
  lookupServerMediaSessionCompletionFunc *const completionFunc;
  void *const completionClientData;
};

void MediaServerPluginRTSPServer
::lookupServerMediaSession(UsageEnvironment &env, char const *streamName,
                           lookupServerMediaSessionCompletionFunc *completionFunc,
                           void *completionClientData,
                           Boolean isFirstLookupInSession) {
  if (!completionFunc) abort();
    // this function seems to be called for each subsession.
    // when we already have a ServerMediaSession for the first subsession,
    // return this stream, the stream of the second subsession will not work
  ServerMediaSession* sms = getServerMediaSession(streamName);
  if (sms && &(sms->envir()) == (&env)) {
    env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName
        << "): returning existing ServerMediaSession " << sms << " with same env\n";
    (*completionFunc)(completionClientData,sms);
    return;
  }
    // called from the thread of the new rtsp connection (env-thread): lock recursive mutex
  std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
  auto it(stream_map.find(streamName));
  if (it == stream_map.end()) {
    env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName
        << "): no such stream in stream_map, streamManager->GetStream will call the cb later\n";
    LookupCompletionFuncData *context = new LookupCompletionFuncData(this,env,streamName,completionFunc,completionClientData);
    streamManager->GetStream(streamName, context, &MediaServerPluginRTSPServer::GetStreamCb);
  } else {
    ServerMediaSession *sms = createServerMediaSession(env,streamName,it->second);
    env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName
        << "): found stream in stream_map, returning new ServerMediaSession " << sms << " with existing stream\n";
    (*completionFunc)(completionClientData,sms);
  }
}

void MediaServerPluginRTSPServer::GetStreamCb(void *cb_context,const TStreamPtr &stream) {
  LookupCompletionFuncData *l = (LookupCompletionFuncData*)cb_context;
  l->self->getStreamCb(l,stream);
  delete l;
}

void MediaServerPluginRTSPServer::getStreamCb(const MediaServerPluginRTSPServer::LookupCompletionFuncData *l,
                                              const TStreamPtr &stream) {
    // called from some thread in the executable (or from my own thread, direct callback): lock recursive_mutex
  ServerMediaSession *sms = nullptr;
  if (stream) {
    std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
    std::shared_ptr<StreamMapEntry> e(new StreamMapEntry(
                                            stream,[this,name=l->streamName]() {
                                              std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
                                              stream_map.erase(name);
                                            }));
    stream_map[l->streamName] = e;
    sms = createServerMediaSession(l->env, l->streamName.c_str(), e);
  }
  l->env << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str()
         << "): returning new ServerMediaSession " << sms << " with new stream\n";
  (*(l->completionFunc))(l->completionClientData, sms);
}

ServerMediaSession *MediaServerPluginRTSPServer::createServerMediaSession(UsageEnvironment &env, const char *stream_name, const std::shared_ptr<StreamMapEntry> &e) {
  ServerMediaSession *sms = nullptr;
  if (e) {
    const SubsessionInfo *const *sl(e->getSubsessionInfoList());
    if ((sl) && (*sl)) {
      sms = ServerMediaSession::createNew(env, stream_name, nullptr, "MediaServerPlugin");
      for (;*sl;sl++) {
        MyServerMediaSubsession *s = MyServerMediaSubsession::createNew(env, stream_name, e, *sl);
        sms->addSubsession(s);
      }
      addServerMediaSession(sms);
    }
  }
  return sms;
}
























class RTCMediaLib {
public:
  RTCMediaLib(IRTCStreamFactory *streamManager,const RTSPParameters &params)
    : streamManager(streamManager),params(params),
      worker_thread([this](void) {
        scheduler = BasicTaskScheduler::createNew();
        scheduler->assert_threads = true;
        env = new DeletableUsageEnvironment(*scheduler);
        {
          std::unique_lock<std::mutex> lck(mtx);
          watchVariable = 0;
          cv.notify_one();
        }
        work();
        delete env; env = nullptr;
        delete scheduler; scheduler = nullptr;
      }) {
    std::unique_lock<std::mutex> lck(mtx);
    while (watchVariable) cv.wait(lck);
  }
  ~RTCMediaLib(void) {
    watchVariable = 1;
    worker_thread.join();
  }
private:
  void work(void) {
    MediaServerPluginRTSPServer *server = MediaServerPluginRTSPServer::createNew(*env,params,streamManager);
    scheduler->doEventLoop(&watchVariable);
    Medium::close(server);
    server = nullptr;
  }
private:
  IRTCStreamFactory *const streamManager;
  RTSPParameters params;
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


static const char *const rtc_media_lib_api_version = RTCMEDIALIB_API_VERSION;


    // will return the API version of the Library.
    // when the interface_api_version_of_caller does not match,
    // the library will not call the streamManager.
extern "C" RTCMEDIALIB_API
const char *initializeRTCMediaLib(
              const char *interface_api_version_of_caller,
              IRTCStreamFactory *streamManager,
              const RTSPParameters &params) {
  if (0 == strcmp(interface_api_version_of_caller,rtc_media_lib_api_version)) {
      // unique_ptr so that threads will be stopped when closing the app
    static std::unique_ptr<RTCMediaLib> impl;
      // first close previous instance and free all ports
    impl = std::unique_ptr<RTCMediaLib>();
      // afterwards create new instance
    impl = std::unique_ptr<RTCMediaLib>(new RTCMediaLib(streamManager,params));
  }
  return rtc_media_lib_api_version;
}

