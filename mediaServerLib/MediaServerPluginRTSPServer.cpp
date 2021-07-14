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

#include <deque>
#include <iostream>
#include <sstream>
#include <iomanip>

template<class T>
std::string ToString(const T &t) {
  std::ostringstream o;
  o << t;
  return o.str();
}

static const char *SubsessionInfoToString(const SubsessionInfo &ssi) {
  switch (ssi.GetFormat()) {
    case RTCFormatJPEG : return "JPEG";
    case RTCFormatH264 : return "H264";
    case RTCFormatYUVI420: return "YUVI420";
    case RTCFormatUnknown: return ssi.getRtpPayloadFormatName();
  }
  return "undefined_format_value";
}

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

static inline
void PrintBytes(const uint8_t *data, int size, int64_t time) {
  std::cout << time << ':' << std::setw(5) << size << std::hex;
  for (int i=0;i<32 && i < size;i++) std::cout << ' ' << std::setw(2) << std::setfill('0') << (uint32_t)(data[i]);
  std::cout << std::dec << std::endl;
}


class MediaServerPluginRTSPServer::StreamMapEntry : public std::enable_shared_from_this<MediaServerPluginRTSPServer::StreamMapEntry> {
  StreamMapEntry(UsageEnvironment &env,const TStreamPtr &stream,std::function<void(void)> &&on_close);
public:
  static std::shared_ptr<StreamMapEntry> Create(UsageEnvironment &env,const TStreamPtr &stream,std::function<void(void)> &&on_close) {
    // std::make_shared does not work in because
    //  it cannot access the private constructor
//    return std::make_shared<StreamMapEntry>(env,stream,std::move(on_close));
    return std::shared_ptr<StreamMapEntry>(new StreamMapEntry(env,stream,std::move(on_close)));
  }
  ~StreamMapEntry(void);
  const SubsessionInfo *const *getSubsessionInfoList(void) const {return subsession_info_list;}
  typedef std::function<void(const Frame&)> FrameFunction;
  class RegistrationEntry;
  class Registration;
  std::shared_ptr<Registration> connect(const SubsessionInfo *info,FrameFunction &&f);
  unsigned int printConnections(const std::string &url,std::ostream &o) const;
  UsageEnvironment &env;
private:
  std::shared_ptr<IRTCStream> stream;
  const std::function<void(void)> on_close;
  static void OnClose(void *context) {reinterpret_cast<StreamMapEntry*>(context)->onClose();}
  TaskToken delayed_close_task = nullptr;
  void onClose(void);
  void resetStream(void);
  void scheduleCloseTask(bool scedule);
  friend class Registration;
  void disconnect(Registration *reg);
  struct FrameFunctionMap;
  static void OnH264NalCallback(const FrameFunctionMap &fm, const uint8_t *buffer, int bufferSize, const int64_t frameTime);
  static void OnH264FrameCallback(const FrameFunctionMap &fm, const uint8_t *buffer, int bufferSize, const int64_t frameTime);
  static void OnFrameCallback(void *callerId, const SubsessionInfo *info, const uint8_t *buffer, int bufferSize, const int64_t frameTime);
  mutable std::recursive_mutex registration_mutex;
  class RegistrationEntry;
  std::map<const SubsessionInfo*,FrameFunctionMap> registration_map;
  const SubsessionInfo *const *subsession_info_list;
};

class MediaServerPluginRTSPServer::StreamMapEntry::Registration {
  Registration(const std::shared_ptr<StreamMapEntry> &map_entry,const SubsessionInfo *info)
    : env(map_entry->env),info(info),map_entry(map_entry) {
    env << "MediaServerPluginRTSPServer::StreamMapEntry::Registration(" << this << ")::Registration(" << map_entry.get() << ")\n";
  }
public:
    // only StreamMapEntry::connect calls Create:
  static std::shared_ptr<Registration> Create(const std::shared_ptr<StreamMapEntry> &map_entry,const SubsessionInfo *info) {
    return std::shared_ptr<Registration>(new Registration(map_entry,info));
//    I would like to write
//    return std::make_shared<Registration>(map_entry,info);
//    but this is impossible because std::make_shared cannot access the private constructor
  }
  ~Registration(void) {
    env << ("MediaServerPluginRTSPServer::StreamMapEntry::Registration(" + ToString(this) + ")::~Registration start\n").c_str();
    disconnect();
    env << ("MediaServerPluginRTSPServer::StreamMapEntry::Registration(" + ToString(this) + ")::~Registration end\n").c_str();
  }
private:
  void disconnect(void) {
    std::shared_ptr<StreamMapEntry> e(map_entry.lock());
    if (e) {
      env << "MediaServerPluginRTSPServer::StreamMapEntry::Registration(" << this << ")::disconnect: calling " << e.get() << "->disconnect\n";
      e->disconnect(this); // will reset the map_entry
    } else {
      env << ("MediaServerPluginRTSPServer::StreamMapEntry::Registration(" + ToString(this) + ")::disconnect: nothing to disconnect\n").c_str();
    }
  }
public:
  UsageEnvironment &env;
  const SubsessionInfo *const info;
private:
  friend class RegistrationEntry;
  std::weak_ptr<StreamMapEntry> map_entry;
};

class MediaServerPluginRTSPServer::StreamMapEntry::RegistrationEntry {
public:
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
  void swap(RegistrationEntry &e) {
    func.swap(e.func);
    reg.swap(e.reg);
  }
  FrameFunction func;
  std::weak_ptr<Registration> reg;
};

struct MediaServerPluginRTSPServer::StreamMapEntry::FrameFunctionMap : public std::map<Registration*,RegistrationEntry> {
  FrameFunctionMap(void) : h264_profile_level_id(0) {}
  void callFunctions(const uint8_t *buffer, int bufferSize, const int64_t frameTime) const {
    const Frame f(buffer,bufferSize,frameTime);
    for (auto &it : *this) it.second.func(f);
  }
  void setH264ProfileLevelId(unsigned int x) {h264_profile_level_id = x;}
  void setH264Sps64(const std::shared_ptr<const char[]> &x) {h264_sps64 = x;}
  void setH264Pps64(const std::shared_ptr<const char[]> &x) {h264_pps64 = x;}
  unsigned int h264_profile_level_id;
  std::shared_ptr<const char[]> h264_sps64,h264_pps64;
};


MediaServerPluginRTSPServer::StreamMapEntry::StreamMapEntry(UsageEnvironment &env,const TStreamPtr &stream,
                                                            std::function<void(void)> &&on_close)
                                            :env(env),stream(stream),on_close(std::move(on_close)) {
  if (!stream) abort();
    // RegisterOnClose might call OnClose early, so lock the mutex:
  std::lock_guard<std::recursive_mutex> lock(registration_mutex);
  subsession_info_list = stream->getSubsessionInfoList();
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::StreamMapEntry:";
  for (const SubsessionInfo *const*s=subsession_info_list;*s;s++) env << " " << SubsessionInfoToString(**s);
  env << "\n";
}

MediaServerPluginRTSPServer::StreamMapEntry::~StreamMapEntry(void) {
  scheduleCloseTask(false);
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::~StreamMapEntry\n";
  {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    registration_map.clear();
  }
  stream.reset();
//  resetStream();
    // defensive programming: in case of programming error segfault as early as possible:
  subsession_info_list = nullptr;
}

void MediaServerPluginRTSPServer::StreamMapEntry::scheduleCloseTask(bool scedule) {
  if (scedule || delayed_close_task) {
    if (env.taskScheduler().isSameThread()) {
      if (scedule) env.taskScheduler().rescheduleDelayedTask(delayed_close_task,15000000,OnClose,this);
      else env.taskScheduler().unscheduleDelayedTask(delayed_close_task);
    } else {
      Semaphore sem;
      env.taskScheduler().executeCommand(
        [this,&sem,s=scedule](uint64_t) {
          if (s) env.taskScheduler().rescheduleDelayedTask(delayed_close_task,15000000,OnClose,this);
          else env.taskScheduler().unscheduleDelayedTask(delayed_close_task);
          sem.post();
        });
      sem.wait();
    }
  }
}



std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry::Registration>
MediaServerPluginRTSPServer::StreamMapEntry::connect(const SubsessionInfo *info,FrameFunction &&f) {
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::connect(" << SubsessionInfoToString(*info) << "): start\n";
  scheduleCloseTask(false);
  if (!stream) abort();
  std::shared_ptr<Registration> reg;
  {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    auto &r(registration_map[info]);
    reg = Registration::Create(shared_from_this(),info);
    r[reg.get()].swap(RegistrationEntry(std::move(f),reg));
  }
    // setting the callback many times does not hurt:
  stream->RegisterOnFrame(this,StreamMapEntry::OnFrameCallback);
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::connect returns " << reg.get() << "\n";
  return reg;
}

void MediaServerPluginRTSPServer::StreamMapEntry::disconnect(Registration *reg) {
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::disconnect(" << SubsessionInfoToString(*reg->info) << "): start\n";
  std::lock_guard<std::recursive_mutex> lock(registration_mutex);
  auto it(registration_map.find(reg->info));
  if (it == registration_map.end()) abort();
    // will call the destructor of the RegistrationEntry wich in turn
    // will invalidate the registration and call the FrameCb with an emty Frame
  if (it->second.erase(reg) != 1) abort();
  if (it->second.empty()) {
    registration_map.erase(it);
    if (registration_map.empty()) {
      env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::disconnect: going to deregister the entire stream in 15 seconds if no one needs it\n";
      scheduleCloseTask(true);
    }
  }
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::disconnect(" << SubsessionInfoToString(*reg->info) << "): end, "
         "registrations: " << (int)(registration_map.size()) << "\n";
}

void MediaServerPluginRTSPServer::StreamMapEntry::resetStream(void) {
  // releasing the stream might lead to the destruction of the stream object
  // which might lead to joining the thread the callback comes from.
  // Therefore: do te destruction in a different thread
  if (!stream) return;
  const bool same_thread = env.taskScheduler().isSameThread();
  if (same_thread) {
    env << ("MediaServerPluginRTSPServer::StreamMapEntry::resetStream: resetting " + ToString(stream.get()) + "in the same thread\n").c_str();
    stream.reset();
    env << ("MediaServerPluginRTSPServer::StreamMapEntry::resetStream: reset " + ToString(stream.get()) + " in the same thread\n").c_str();
  } else {
    env << ("MediaServerPluginRTSPServer::StreamMapEntry::resetStream: resetting " + ToString(stream.get()) + " in another thread\n").c_str();
    TStreamPtr tmp;
    stream.swap(tmp);
    env.taskScheduler().executeCommand(
      [tmp,e=&env](uint64_t) {
        *e << ("MediaServerPluginRTSPServer::StreamMapEntry::resetStream::l: resetting " + ToString(tmp.get()) + "\n").c_str();
      });
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::onClose(void) {
  env << "MediaServerPluginRTSPServer::StreamMapEntry(" << this << ")::onClose\n";
    // called from the executables threads:
  {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    registration_map.clear();
    subsession_info_list = nullptr;
  }
  resetStream();
  if (on_close) on_close();
}

unsigned int MediaServerPluginRTSPServer::StreamMapEntry::printConnections(const std::string &url,std::ostream &o) const {
  unsigned int rval = 0;
  std::lock_guard<std::recursive_mutex> lock(registration_mutex);
  for (auto &it : registration_map) {
    const unsigned int c = it.second.size();
    rval += c;
  }
  if (rval > 0) {
    o << "Stream url: " << url;
    int track_id = 0;
    for (auto &it : registration_map) {
      const unsigned int c = it.second.size();
      o << ", " << SubsessionInfoToString(*it.first) << "(" << track_id << "): " << c << " connection(s)" ;
      track_id++;
    }
    o << "\n";
  }
  return rval;
}


void MediaServerPluginRTSPServer::StreamMapEntry::OnH264NalCallback(const FrameFunctionMap &fm, const uint8_t *buffer, int bufferSize, const int64_t frameTime) {
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
  fm.callFunctions(buffer,bufferSize,frameTime);
}

void MediaServerPluginRTSPServer::StreamMapEntry::OnH264FrameCallback(const FrameFunctionMap &fm, const uint8_t *buffer, int bufferSize, const int64_t frameTime) {
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
    OnH264NalCallback(fm,p,end-p,frameTime);
    break;
    nal_start_found:
    const uint8_t *p_next = p0 + 3;
    if (p0 > p) {
      if (p0[-1]==0) p0--;
      if (p0 > p) OnH264NalCallback(fm,p,p0-p,frameTime);
    }
    p = p_next;
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::OnFrameCallback(void *callerId, const SubsessionInfo *info, const uint8_t *buffer, int bufferSize, const int64_t frameTime) {
  StreamMapEntry &e(*reinterpret_cast<MediaServerPluginRTSPServer::StreamMapEntry*>(callerId));
  if (!info || !buffer || bufferSize == 0) {
    e.onClose();
    return;
  }
  std::lock_guard<std::recursive_mutex> lock(e.registration_mutex);
  const auto r(e.registration_map.find(info));
  if (r != e.registration_map.end()) {
    switch (info->GetFormat()) {
      case RTCFormatH264:
        OnH264FrameCallback(r->second,buffer,bufferSize,frameTime);
        break;
      default:
        r->second.callFunctions(buffer,bufferSize,frameTime);
        break;
    }
  }
}



static
int CreateAcceptSocket(UsageEnvironment& env, Port ourPort, unsigned int bind_to_interface) {
  int accept_fd = ::socket(AF_INET,SOCK_STREAM,0);
  if (accept_fd < 0) {
    env << "socket() failed: " << env.getErrno() << "\n";
    return -1;
  }
  const int yes = -1; // all bits set to 1
  if (0 != ::setsockopt(accept_fd,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char*)(&yes),sizeof(yes))) {
    env << "setsockopt(SO_EXCLUSIVEADDRUSE) failed: " << env.getErrno() << "\n";
    ::closeSocket(accept_fd);
    return -1;
  }
  struct sockaddr_in sock_addr;
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.s_addr = htonl(bind_to_interface);
  sock_addr.sin_port = ourPort.num(); // already network order
  if (0 != bind(accept_fd,(struct sockaddr*)(&sock_addr),sizeof(sock_addr))) {
    env << "bind() failed: " << env.getErrno() << "\n";
    ::closeSocket(accept_fd);
    return -1;
  }
  if (0 != ::listen(accept_fd,20)) {
    env << "listen() failed: " << env.getErrno() << "\n";
    ::closeSocket(accept_fd);
    return -1;
  }
  return accept_fd;
}



MediaServerPluginRTSPServer*
MediaServerPluginRTSPServer::createNew(UsageEnvironment &env, const RTSPParameters &params, IRTCStreamFactory* streamManager) {
  const int ourSocketIPv4 = CreateAcceptSocket(env, Port(params.port), params.bind_to_interface);
  if (ourSocketIPv4 < 0) {
    env << "MediaServerPluginRTSPServer::createNew: opening rtsp port " << params.port << " failed\n";
    return nullptr;
  }
  env << "MediaServerPluginRTSPServer::createNew: CreateAcceptSocket(" << params.port << ") returned "
      << ourSocketIPv4 << "\n";
  const int ourSocketIPv6 = setUpOurSocket(env, Port(params.port), AF_INET6);
  if (ourSocketIPv6 < 0) {
    env << "MediaServerPluginRTSPServer::createNew: opening IPV6 rtsp port " << params.port << " failed\n";
  } else {
    env << "MediaServerPluginRTSPServer::createNew: setUpOurSocket(" << params.port << ",IPV6) returned "
        << ourSocketIPv6 << "\n";
  }
  int m_HTTPServerSocket = -1;
  int m_HTTPsServerSocket = -1;
  if (params.httpPort) {
    m_HTTPServerSocket = CreateAcceptSocket(env, params.httpPort, params.bind_to_interface);
    if (m_HTTPServerSocket < 0) {
      env << "MediaServerPluginRTSPServer::createNew: opening http port " << params.httpPort << " failed\n";
      if (ourSocketIPv6 >= 0) ::closeSocket(ourSocketIPv6);
      ::closeSocket(ourSocketIPv4);
      return nullptr;
    }
    env << "MediaServerPluginRTSPServer::createNew: CreateAcceptSocket(" << params.httpPort << ") returned "
        << m_HTTPServerSocket << "\n";
    if (params.httpsPort) {
      m_HTTPsServerSocket = CreateAcceptSocket(env, params.httpsPort, params.bind_to_interface);
      if (m_HTTPsServerSocket < 0) {
        env << "MediaServerPluginRTSPServer::createNew: opening https port " << params.httpsPort << " failed\n";
        ::closeSocket(m_HTTPServerSocket);
        if (ourSocketIPv6 >= 0) ::closeSocket(ourSocketIPv6);
        ::closeSocket(ourSocketIPv4);
        return nullptr;
      }
      env << "MediaServerPluginRTSPServer::createNew: CreateAcceptSocket(" << params.httpsPort << ") returned "
          << m_HTTPsServerSocket << "\n";
    }
  }
  return new MediaServerPluginRTSPServer(env, ourSocketIPv4, ourSocketIPv6, m_HTTPServerSocket, m_HTTPsServerSocket, params, streamManager);
}

MediaServerPluginRTSPServer::MediaServerPluginRTSPServer(UsageEnvironment &env, int ourSocketIPv4, int ourSocketIPv6,
                                                         int m_HTTPServerSocket, int m_HTTPsServerSocket, 
                                                         const RTSPParameters &params, IRTCStreamFactory *streamManager)
                            :RTSPServer(env, ourSocketIPv4, ourSocketIPv6, Port(params.port), NULL, 65),
                             m_HTTPServerSocket(m_HTTPServerSocket),m_HTTPsServerSocket(m_HTTPsServerSocket),
                             params(params), streamManager(streamManager),
                             m_urlPrefix(rtspURLPrefix(params.bind_to_interface ? ourSocketIPv4 : -1)) // allocated with strDup, not strdup. free with delete[]
 {
  if (m_HTTPServerSocket >= 0) {
    env.taskScheduler().turnOnBackgroundReadHandling(m_HTTPServerSocket,
      incomingConnectionHandlerHTTP, this);
  }
  if (m_HTTPsServerSocket >= 0) {
    env.taskScheduler().turnOnBackgroundReadHandling(m_HTTPsServerSocket,
      incomingConnectionHandlerHTTPoverSSL, this);
  }
    // Schedule status info task (run periodically)
  generate_info_string_task = env.taskScheduler().scheduleDelayedTask(1000000, GenerateInfoString, this);
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
  env.taskScheduler().executeCommand([rval,clientSocket,p=ourServer.params.httpPort,certpath,keypath,&sem](uint64_t) {
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
  MyFrameSource(const MyFrameSource&);
  MyFrameSource &operator=(MyFrameSource&);
  MyFrameSource(UsageEnvironment &env) : FramedSource(env) {
    env << "MyFrameSource(" << this << ")::MyFrameSource\n";
  }
  ~MyFrameSource(void) override {
    envir().taskScheduler().assertSameThread();
      // release connection before cleanup so that no new framecallbacks will be deliverd
    frame_connection.reset();

      // This destructor call may come from within a frame callback.
      // The frame callback will continue after the destructor has finished and will access
      // the deleted object.

    std::lock_guard<std::mutex> lock(registered_tasks_mutex);
    if (!registered_tasks.empty()) {
      do {
        auto registered_task = registered_tasks.front();
        registered_tasks.pop_front();
        if (envir().taskScheduler().cancelCommand(registered_task)) {
          envir() << ("MyFrameSource(" + ToString(this) + ")::~MyFrameSource: cancelled (" + std::to_string(registered_task) + ")\n").c_str();
        } else {
          envir() << ("MyFrameSource(" + ToString(this) + ")::~MyFrameSource: cancelling (" + std::to_string(registered_task) + ") failed, "
                      "this can happen when I want to cancel my own task\n").c_str();
        }
      } while (!registered_tasks.empty());
    } else {
      envir() << ("MyFrameSource(" + ToString(this) + ")::~MyFrameSource: no task to cancel\n").c_str();
    }
  }
  void connect(MediaServerPluginRTSPServer::StreamMapEntry &e,
               const SubsessionInfo *info) {
//    envir() << "MyFrameSource::connect\n";
    frame_connection = e.connect(info,
          [this](const Frame &f) {
              // called from some thread outside the plugin
            if (f.size == 0) {
                // no more frames for this SubsessionInfo
              envir() << "MyFrameSource::connect::l: empty frame received\n";
            } else {
              std::lock_guard<std::mutex> lock(registered_tasks_mutex);
              const uint64_t registered_task = envir().taskScheduler().executeCommand(
                [this,f](uint64_t task_nr) {
                    // this is the actual frame callback.
                    // It is called from the connections UsageEnvironment thread
                  my_frame_queue.push_back(f); // Frame contains shared Ptr to data
                  deliverFrame();
                  std::lock_guard<std::mutex> lock(registered_tasks_mutex);
                  if (registered_tasks.front() != task_nr) abort();
                  registered_tasks.pop_front();
                  envir() << ("MyFrameSource::connect::l::l: frame in connection thread, dequeued task(" + std::to_string(task_nr) + ")\n").c_str();
                });
              envir() << ("MyFrameSource::connect::l: frameCb, queueing frame -> task(" + std::to_string(registered_task) + ")\n").c_str();
              registered_tasks.push_back(registered_task);
            }
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
      envir() << "MyFrameSource(" << this << ")::deliverFrame: frame_size(" << frame_size << ") > fMaxSize(" << fMaxSize << ")\n";
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
    my_frame_queue.pop_front();
    FramedSource::afterGetting(this);
  }
  void doGetNextFrame(void) override {
    deliverFrame();
  }
  std::deque<Frame> my_frame_queue;
  std::deque<uint64_t> registered_tasks;
  std::mutex registered_tasks_mutex;
  std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry::Registration> frame_connection;
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
// TODO: obviousely we can end up with many ServerMediaSession objects with the same name.
// But only (the last) one ist stored in the GenericMediaServer object.
// This may or may not lead to troubles, I do not know.
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
    std::shared_ptr<StreamMapEntry> e(StreamMapEntry::Create(envir(),
                                            stream,[this,name=l->streamName]() {
                                              if (envir().taskScheduler().isSameThread()) {
                                                closeAllClientSessionsForServerMediaSession(name.c_str());
                                                removeServerMediaSession(name.c_str());
                                                std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
                                                stream_map.erase(name);
                                              } else {
                                                Semaphore sem;
                                                envir().taskScheduler().executeCommand(
                                                  [this,name,&sem](uint64_t) {
                                                    closeAllClientSessionsForServerMediaSession(name.c_str());
                                                    removeServerMediaSession(name.c_str());
                                                    std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
                                                    stream_map.erase(name);
//                                                    sem.post();
                                                  });
//                                                sem.wait();
                                              }
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


class LoggingUsageEnvironment : public BasicUsageEnvironment {
public:
  LoggingUsageEnvironment(TaskScheduler &scheduler,IRTCStreamFactory *streamManager)
    : BasicUsageEnvironment(scheduler),streamManager(streamManager) {}
private:
  IRTCStreamFactory *const streamManager;
  UsageEnvironment& operator<<(char const* str) override {
    streamManager->OnLog(std::string(str?str:"(NULL)"));
    return *this;
  }
  UsageEnvironment& operator<<(int i) override {
    std::ostringstream o;
    o << i;
    streamManager->OnLog(o.str());
    return *this;
  }
  UsageEnvironment& operator<<(unsigned u) override {
    std::ostringstream o;
    o << u;
    streamManager->OnLog(o.str());
    return *this;
  }
  UsageEnvironment& operator<<(double d) override {
    std::ostringstream o;
    o << d;
    streamManager->OnLog(o.str());
    return *this;
  }
  UsageEnvironment& operator<<(void* p) override {
    std::ostringstream o;
    o << p;
    streamManager->OnLog(o.str());
    return *this;
  }
};

UsageEnvironment *MediaServerPluginRTSPServer::createNewUsageEnvironment(TaskScheduler &scheduler) {
  return new LoggingUsageEnvironment(scheduler,streamManager);
}


void MediaServerPluginRTSPServer::GenerateInfoString(void *context) {
  reinterpret_cast<MediaServerPluginRTSPServer*>(context)->generateInfoString();
}

void MediaServerPluginRTSPServer::generateInfoString(void)
{
  unsigned int connections = 0;
  std::stringstream ss;
  {
    std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
    ss << "---- MediaServer: " << stream_map.size() << " Session(s) active ---- " << "url: " << m_urlPrefix.get() << "[cameraNum]-[streamId]";
    if (params.httpPort)
      ss << " | RTSP-over-HTTP tunnel (Port " << params.httpPort << ")";
    else
      ss << " | no RTSP-over-HTTP tunnel";
    if (params.httpsPort)
      ss << " | RTSP-over-HTTP-over-SSL tunnel (Port " << params.httpsPort << ")";
    else
      ss << " | no RTSP-over-HTTP-over-SSL tunnel";
    ss << "\n";
    for (auto &it : stream_map) {
      connections += it.second->printConnections(m_urlPrefix.get()+it.first,ss);
    }
  }
  ss << "Media Server Connections: " << connections << "\n";
  ss << std::endl;
  streamManager->OnStatsInfo(ss.str().c_str());
  // reschedule the next status info task
  const unsigned int generate_info_string_interval = 10; //[sec]
  envir().taskScheduler().rescheduleDelayedTask(generate_info_string_task, generate_info_string_interval * 1000000ULL, GenerateInfoString, this);
}

















class RTCMediaLib {
public:
  static RTCMediaLib *Create(IRTCStreamFactory *streamManager,const RTSPParameters &params) {
    RTCMediaLib *rval = new RTCMediaLib(streamManager,params);
    if (!rval->isRunning()) {
      delete rval;
      rval = 0;
    }
    return rval;
  }
  ~RTCMediaLib(void) {
    if (env) *env << "RTCMediaLib::~RTCMediaLib::l: end\n";
    watchVariable = 1;
    worker_thread.join();
  }
private:
  RTCMediaLib(IRTCStreamFactory *streamManager,const RTSPParameters &params)
    : streamManager(streamManager),params(params),
      worker_thread([this](void) {
        scheduler = BasicTaskScheduler::createNew();
        scheduler->assert_threads = true;
        env = new LoggingUsageEnvironment(*scheduler,RTCMediaLib::streamManager);
        *env << "RTCMediaLib::RTCMediaLib::l: start\n";
        MediaServerPluginRTSPServer *server
          = MediaServerPluginRTSPServer::createNew(*env,RTCMediaLib::params,RTCMediaLib::streamManager);
        if (server) {
          *env << "RTCMediaLib::RTCMediaLib::l: running...\n";
          {
            std::unique_lock<std::mutex> lck(mtx);
            watchVariable = 0;
            cv.notify_one();
          }
          scheduler->doEventLoop(&watchVariable);
          *env << "RTCMediaLib::RTCMediaLib::l: stopping...\n";
        } else {
          *env << "RTCMediaLib::RTCMediaLib::l: server creation failed\n";
        }
        Medium::close(server);
        server = nullptr;
        *env << "RTCMediaLib::RTCMediaLib::l: end\n";
        if (!env->reclaim()) abort();
        env = nullptr;
        delete scheduler; scheduler = nullptr;
        if (!server) {
            // when construction has failed: notify only after cleanup is finished
          std::unique_lock<std::mutex> lck(mtx);
          watchVariable = 0;
          cv.notify_one();
        }
      }) {
    std::unique_lock<std::mutex> lck(mtx);
    while (watchVariable) cv.wait(lck);
  }
  bool isRunning(void) const {return scheduler;}
private:
  IRTCStreamFactory *const streamManager;
  RTSPParameters params;
  BasicTaskScheduler *scheduler = nullptr;
  UsageEnvironment *env = nullptr;
  char volatile watchVariable = 1;
  std::thread worker_thread;
    // mutex and condition variable only to be able to wait for thread to start:
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
  OutPacketBuffer::maxSize = 1024*512;
  if (0 == strcmp(interface_api_version_of_caller,rtc_media_lib_api_version)) {
      // unique_ptr so that threads will be stopped when closing the app
    static std::unique_ptr<RTCMediaLib> impl;
      // first close previous instance and free all ports
    impl = std::unique_ptr<RTCMediaLib>();
      // afterwards create new instance
    if (streamManager) {
      impl = std::unique_ptr<RTCMediaLib>(RTCMediaLib::Create(streamManager,params));
      if (!impl) {
        return "server starting failed, probably port problem. Check the log.";
      }
    }
  }
  return rtc_media_lib_api_version;
}

