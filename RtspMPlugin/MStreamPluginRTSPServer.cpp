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

#include "MStreamPluginRTSPServer.hh"
#include "H264VideoStreamDiscreteFramer.hh"
#include "BasicUsageEnvironment.hh"
#include <liveMedia.hh>
#include <Base64.hh>
#include <GroupsockHelper.hh>

#include <string.h>

#include <map>
#include <set>
#include <deque>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <atomic>


//#define ALLOC_STATS
#ifdef ALLOC_STATS

class MemAccounter {
public:
  static MemAccounter &Singleton(void) {
    static MemAccounter m;
    return m;
  }
  void accountAlloc(size_t size) {bins[GetBin(size)] += size;}
  void accountFree(size_t size) {bins[GetBin(size)] -= size;}
  void print(std::ostream &o) const {
    o << "RTSP Plugin C++ Memory:\n";
    size_t s = 32;
    size_t total = 0;
    for (unsigned int i=0;i<nr_of_bins;i++,s<<=1) {
      const size_t bytes = bins[i];
      if (bytes) {
        total += bytes;
        o << s << ": " << bytes << '\n';
      }
    }
    o << "total: " << total << '\n';
  }
private:
  enum {nr_of_bins = 21};
  std::atomic<size_t> bins[nr_of_bins];
  static unsigned int GetBin(size_t size) {
    unsigned int rval = 0;
    while (size > 32) {
      rval++;
      if (rval >= nr_of_bins) return (nr_of_bins-1);
      size >>= 1;
    }
    return rval;
  }
  MemAccounter(void) {
    for (unsigned int i=0;i<nr_of_bins;i++) bins[i] = 0;
  }
};

void *operator new(size_t size) {
  if (!size) size=1;
  size_t *const rval = (uint64_t*)malloc(sizeof(size_t)+size);
  if (!rval) abort();
  MemAccounter::Singleton().accountAlloc(size);
  *rval = size;
  return rval+1;
}

void operator delete(void *p) noexcept {
  if (!p) return;
  size_t *const d = ((size_t*)p)-1;
  MemAccounter::Singleton().accountFree(*d);
  free(d);
}

void *operator new[](size_t size) {return operator new(size);}
void operator delete[](void *p) noexcept {operator delete(p);}


struct AllocStatEntry {
  AllocStatEntry(void) : alloc_count(0),alloc_size(0) {}
  std::atomic<uint32_t> alloc_count;
  std::atomic<uint64_t> alloc_size;
};

static std::mutex alloc_stat_mutex;
static std::map<std::string,std::unique_ptr<AllocStatEntry> > alloc_stat;

static AllocStatEntry &GetAllocEntry(const std::string &name) {
  std::lock_guard<std::mutex> lock(alloc_stat_mutex);
  std::unique_ptr<AllocStatEntry> &ae(alloc_stat[name]);
  if (!ae) ae = std::make_unique<AllocStatEntry>();
  return *ae;
}

static void PrintAllocInfos(std::ostream &o) {
  o << "RTSP Plugin allocated Frames:\n";
  std::lock_guard<std::mutex> lock(alloc_stat_mutex);
  for (auto &i : alloc_stat) {
    o << i.first << ": " << i.second->alloc_count
      << " / " << i.second->alloc_size << '\n';
  }
}

#endif


class IdContainer {
  static unsigned int GetSequenceId(void) {
    static std::atomic<unsigned int> seq(0);
    return ++seq;
  }
public:
  const unsigned int id;
  IdContainer(void) : id(GetSequenceId()) {}
  IdContainer(const IdContainer &c) : id(c.id) {}
};



template<class T>
std::string ToString(const T &t) {
  std::ostringstream o;
  o << t;
  return o.str();
}

static const char *SubsessionInfoToString(const SubsessionInfo &ssi) {
  return ssi.getRtpPayloadFormatName();
}


struct Frame {
  Frame(void) : size(0), time(0) {}
  Frame(const MediaServerPluginRTSPServer::StreamMapEntry &e,const uint8_t *data,int32_t size,int64_t time);
  const uint32_t size;
  const int64_t time;
  std::shared_ptr<const uint8_t[]> data;
};

static inline
void PrintBytes(const uint8_t *data, int size, int64_t time) {
  std::cout << time << ':' << std::setw(5) << size << std::hex;
  for (int i=0;i<32 && i < size;i++) std::cout << ' ' << std::setw(2) << std::setfill('0') << (uint32_t)(data[i]);
  std::cout << std::dec << std::endl;
}


class MediaServerPluginRTSPServer::StreamMapEntry : public std::enable_shared_from_this<MediaServerPluginRTSPServer::StreamMapEntry>, public IdContainer {
  StreamMapEntry(UsageEnvironment &env,const std::shared_ptr<IMStream> &stream,const std::string &name,std::function<void(const std::string&)> &&on_close);
public:
  static std::shared_ptr<StreamMapEntry> Create(UsageEnvironment &env,const std::shared_ptr<IMStream> &stream,const std::string &name,std::function<void(const std::string&)> &&on_close) {
    // std::make_shared does not work in because
    //  it cannot access the private constructor
//    return std::make_shared<StreamMapEntry>(env,stream,std::move(on_close));
    return std::shared_ptr<StreamMapEntry>(new StreamMapEntry(env,stream,name,std::move(on_close)));
  }
  ~StreamMapEntry(void);
  const SubsessionInfo *const *getSubsessionInfoList(void) const {return subsession_info_list;}
  typedef std::function<void(const Frame&)> FrameFunction;
  class Registration;
  std::unique_ptr<Registration> connect(const SubsessionInfo *info,FrameFunction &&f);
  unsigned int printConnections(const std::string &url,std::ostream &o) const;
  void keepAlive(void);
  UsageEnvironment &env;
  const std::string name;
private:
  const std::shared_ptr<IMStream> stream;
  const std::function<void(const std::string&)> on_close;
  TaskToken delayed_keep_task = nullptr; // must only be accessed from plugin thread(=own thread)
  bool i_want_to_die = false;            // must only be accessed from plugin thread(=own thread)
  void onClose(void);
  static void ScheduleKeepTaskHelper(std::shared_ptr<StreamMapEntry> *ptr);
  void scheduleCancelTaskHelper(void);
  void cancelKeepAlive(void);
  friend class Registration;
  void remember(Registration *reg);
  void forget(Registration *reg);
  struct RegistrationSet;
  static void OnH264NalCallback(const RegistrationSet &rs, const uint8_t *buffer, int bufferSize, const int64_t frameTime);
  static void OnH264FrameCallback(const RegistrationSet &rs, const uint8_t *buffer, int bufferSize, const int64_t frameTime);
  static void OnFrameCallback(void *callerId, const SubsessionInfo *info, const uint8_t *buffer, int bufferSize, const TimeType &frameTime);
  mutable std::recursive_mutex registration_mutex;
  std::map<const SubsessionInfo*,RegistrationSet> registration_map;
  const SubsessionInfo *const *subsession_info_list;
};

Frame::Frame(const MediaServerPluginRTSPServer::StreamMapEntry &e,const uint8_t *data,int32_t size,int64_t time)
      :size((data && size>0)?size:0),time(time) {
  if (Frame::size) {
#ifdef ALLOC_STATS
    AllocStatEntry &ae(GetAllocEntry(e.name));
#endif
    Frame::data = std::shared_ptr<const uint8_t[]>(
      new uint8_t[Frame::size],
      [s=Frame::size
#ifdef ALLOC_STATS
        ,&ae
#endif
      ](const uint8_t *d) {
#ifdef ALLOC_STATS
        ae.alloc_size -= s;
        ae.alloc_count--;
#endif
        delete[] d;
      });
    memcpy(const_cast<uint8_t*>(Frame::data.get()),data,Frame::size);
#ifdef ALLOC_STATS
    ae.alloc_count++;
    ae.alloc_size += Frame::size;
#endif
  }
}

class MediaServerPluginRTSPServer::StreamMapEntry::Registration : public IdContainer {
  Registration(const std::shared_ptr<StreamMapEntry> &map_entry,
               const SubsessionInfo *info,FrameFunction &&f)
    : map_entry(map_entry),env(map_entry->env),info(info),f(std::move(f)) {
    map_entry->remember(this);
    env << "StreamMapEntry::Registration(" << id << ")::Registration(" << map_entry->name.c_str() << "), use_count: " << map_entry.use_count() << "\n";
  }
  const std::shared_ptr<StreamMapEntry> map_entry;
public:
    // Having a Registration means having a shared_ptr to the StreamMapEntry
    // and thus having a shared_ptr to the stream itself and its internal memory like *info.
    // It cannot guarantee that frames will be received, rather guarantees that no more frames will be received
    // after the destructor is finished.
    // Only StreamMapEntry::connect calls Create:
  static std::unique_ptr<Registration> Create(const std::shared_ptr<StreamMapEntry> &map_entry,
                                              const SubsessionInfo *info,FrameFunction &&f) {
    return std::unique_ptr<Registration>(new Registration(map_entry,info,std::move(f)));
  }
  ~Registration(void) {
    env << "StreamMapEntry::Registration(" << id << "," << map_entry->name.c_str() << ")::~Registration start\n";
    map_entry->forget(this);
    env << "StreamMapEntry::Registration(" << id << "," << map_entry->name.c_str() << ")::~Registration end, use_count:" << (map_entry.use_count()-1) << "\n";
  }
public:
  UsageEnvironment &env;
  const SubsessionInfo *const info;
  const FrameFunction f;
};

struct MediaServerPluginRTSPServer::StreamMapEntry::RegistrationSet : public std::set<Registration*> {
  RegistrationSet(void) : e(0),h264_profile_level_id(0) {}
  void callFunctions(const uint8_t *buffer, int bufferSize, const int64_t frameTime) const {
    const Frame f(*e,buffer,bufferSize,frameTime);
    for (auto &it : *this) it->f(f);
  }
  StreamMapEntry *e;
  void setH264ProfileLevelId(unsigned int x) {h264_profile_level_id = x;}
  void setH264Sps64(const std::shared_ptr<const char[]> &x) {h264_sps64 = x;}
  void setH264Pps64(const std::shared_ptr<const char[]> &x) {h264_pps64 = x;}
  unsigned int h264_profile_level_id;
  std::shared_ptr<const char[]> h264_sps64,h264_pps64;
};


MediaServerPluginRTSPServer::StreamMapEntry::StreamMapEntry(UsageEnvironment &env,const std::shared_ptr<IMStream> &stream,const std::string &name,
                                                            std::function<void(const std::string&)> &&on_close)
                                            :env(env),name(name),stream(stream),on_close(std::move(on_close)) {
  if (!stream) abort();
    // RegisterOnClose might call Destroy early, so lock the mutex:
  std::lock_guard<std::recursive_mutex> lock(registration_mutex);
  subsession_info_list = stream->getSubsessionInfoList();
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::StreamMapEntry:";
  for (const SubsessionInfo *const*s=subsession_info_list;*s;s++) env << " " << SubsessionInfoToString(**s);
  env << "\n";
  stream->RegisterOnFrame(this,StreamMapEntry::OnFrameCallback);
}

MediaServerPluginRTSPServer::StreamMapEntry::~StreamMapEntry(void) {
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::~StreamMapEntry start\n";
  stream->RegisterOnFrame(this,nullptr);
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::~StreamMapEntry: calling onClose\n";
  onClose();
  {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    if (!registration_map.empty()) abort();
  }
    // defensive programming: in case of programming error segfault as early as possible:
  subsession_info_list = nullptr;
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::~StreamMapEntry end\n";
}



std::unique_ptr<MediaServerPluginRTSPServer::StreamMapEntry::Registration>
MediaServerPluginRTSPServer::StreamMapEntry::connect(const SubsessionInfo *info,FrameFunction &&f) {
  return Registration::Create(shared_from_this(),info,std::move(f));
}

void MediaServerPluginRTSPServer::StreamMapEntry::remember(Registration *reg) {
    // only called from the Registration constructor
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::remember(" << SubsessionInfoToString(*reg->info) << "): start\n";
  if (!stream) abort();
  bool call_register;
  {
    std::lock_guard<std::recursive_mutex> lock(registration_mutex);
    call_register = registration_map.empty();
    RegistrationSet &rs(registration_map[reg->info]);
    rs.e = this;
    if (!rs.insert(reg).second) abort();
  }
  if (call_register) 
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::remember end\n";
}

void MediaServerPluginRTSPServer::StreamMapEntry::forget(Registration *reg) {
    // only called from the Registration destructor: from the worker threads, when MyFrameSource is destructed
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::forget(" << SubsessionInfoToString(*reg->info) << "): start\n";
  std::lock_guard<std::recursive_mutex> lock(registration_mutex);
  auto it(registration_map.find(reg->info));
  if (it == registration_map.end()) abort();
    // will call the destructor of the RegistrationEntry wich in turn
    // will invalidate the registration and call the FrameCb with an empty Frame
  const auto erase_rc = it->second.erase(reg);
  if (erase_rc != 1) abort();
  if (it->second.empty()) {
    registration_map.erase(it);
    if (registration_map.empty()) {
      keepAlive();
    }
  }
  env << "StreamMapEntry(" << id << "," <<name.c_str() << ")::forget(" << SubsessionInfoToString(*reg->info) << "): end\n";
}

static void Destroy(void *context) {
  std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> *ptr
    = reinterpret_cast<std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry>*>(context);
  (*ptr)->env << "Destroy(" << (*ptr)->name.c_str() << "): releasing shared_ptr, use_count: " << ((*ptr).use_count()-1) << "\n";
  delete ptr;
}

void MediaServerPluginRTSPServer::StreamMapEntry::ScheduleKeepTaskHelper(std::shared_ptr<StreamMapEntry> *self) {
    // called only from my own thread = plugin thead
  std::shared_ptr<StreamMapEntry> *old_ptr = nullptr;
  if ((*self)->i_want_to_die) {
    if ((*self)->delayed_keep_task) {
      (*self)->env << "StreamMapEntry::ScheduleKeepTaskHelper(" << (*self)->id << "," << (*self)->name.c_str() << "): "
                      "unsceduling KeepAlive task\n";
      old_ptr = (std::shared_ptr<StreamMapEntry>*)
        (*self)->env.taskScheduler().unscheduleDelayedTask((*self)->delayed_keep_task);
    }
  } else {
    (*self)->env << "StreamMapEntry::ScheduleKeepTaskHelper(" << (*self)->id << "," << (*self)->name.c_str() << "): "
                    "going to destroy the StreamMapEntry in 15 seconds if no one needs it\n";
    old_ptr = (std::shared_ptr<StreamMapEntry>*)
      (*self)->env.taskScheduler().rescheduleDelayedTask((*self)->delayed_keep_task,15000000,
                                                         Destroy,self);
  }
  if (old_ptr) {
    (*self)->env << "StreamMapEntry::ScheduleKeepTaskHelper(" << (*self)->id << "," << (*self)->name.c_str() << "): "
                    "releasing old shared_ptr, old use_count: " << old_ptr->use_count() << "\n";
    delete old_ptr;
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::keepAlive(void) {
    // creating shared_from_this() prevents destruction
  std::shared_ptr<StreamMapEntry> *self = new std::shared_ptr<StreamMapEntry>(shared_from_this());
  if (env.taskScheduler().isSameThread()) {
    ScheduleKeepTaskHelper(self);
  } else {
    env << "StreamMapEntry(" << id << "," << (*self)->name.c_str() << ")::keepAlive: "
           "delegating release into plugin thread, use_count: " << self->use_count() << "\n";
    env.taskScheduler().executeCommand([self](uint64_t) {ScheduleKeepTaskHelper(self);});
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::scheduleCancelTaskHelper(void) {
    // called only from my own thread = plugin thead
  i_want_to_die = true;
  if (delayed_keep_task) {
    std::shared_ptr<StreamMapEntry> *old_ptr = (std::shared_ptr<StreamMapEntry>*)
      env.taskScheduler().unscheduleDelayedTask(delayed_keep_task);
    env << "StreamMapEntry(" << id << "," << name.c_str() << ")::scheduleCancelTaskHelper: unscheduled, ";
    if (old_ptr) env << "releasing old shared_ptr, old use_count: " << old_ptr->use_count() << "\n";
    else env << "no old shared_ptr\n";
    delete old_ptr;
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::cancelKeepAlive(void) {
  if (env.taskScheduler().isSameThread()) {
    scheduleCancelTaskHelper();
  } else {
    env << "StreamMapEntry(" << id << "," << name.c_str() << ")::cancelKeepAlive: "
           "delegating cancellation into plugin thread\n";
    env.taskScheduler().executeCommand([this](uint64_t) {
      scheduleCancelTaskHelper();
    });
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::onClose(void) {
  env << "StreamMapEntry(" << id << "," << name.c_str() << ")::onClose: start\n";
  cancelKeepAlive();
  const std::string name_for_logging(name);
  if (on_close) {
    env << "StreamMapEntry(" << id << "," << name.c_str() << ")::onClose: calling on_close cb\n";
    on_close(name);
  }
    // StreamMapEntry may have been deleted, do not use it for logging
  env << "StreamMapEntry(" << id << "," << name_for_logging.c_str() << ")::onClose: end\n";
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


void MediaServerPluginRTSPServer::StreamMapEntry::OnH264NalCallback(const RegistrationSet &rs, const uint8_t *buffer, int bufferSize, const int64_t frameTime) {
/*
      maybe this code will be useful later
    const uint8_t nal_unit_type = (*buffer & 0x1f);
    if (nal_unit_type == 7) {
      if (bufferSize >= 4) {
        rs.setH264ProfileLevelId(
             (((uint32_t)buffer[1])<<16)|(((uint32_t)buffer[2])<<8)|((uint32_t)buffer[3]));
      }
      rs.setH264Sps64(std::shared_ptr<const char[]>(base64Encode((const char*)buffer,bufferSize)));
    } else if (nal_unit_type == 8) {
      rs.setH264Pps64(std::shared_ptr<const char[]>(base64Encode((const char*)buffer,bufferSize)));
    }
*/
  rs.callFunctions(buffer,bufferSize,frameTime);
}

void MediaServerPluginRTSPServer::StreamMapEntry::OnH264FrameCallback(const RegistrationSet &rs, const uint8_t *buffer, int bufferSize, const int64_t frameTime) {
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
    OnH264NalCallback(rs,p,end-p,frameTime);
    break;
    nal_start_found:
    const uint8_t *p_next = p0 + 3;
    if (p0 > p) {
      if (p0[-1]==0) p0--;
      if (p0 > p) OnH264NalCallback(rs,p,p0-p,frameTime);
    }
    p = p_next;
  }
}

void MediaServerPluginRTSPServer::StreamMapEntry::OnFrameCallback(void *callerId, const SubsessionInfo *info, const uint8_t *buffer, int bufferSize, const TimeType &frameTime) {
    // The executable has called the callback, meaning that the stream is still alive an registered.
    // This implies that the StreamMapEntry is not yet destructed,
    // and I can get its address from the callerId, which was given to the executable upon registration of OnFrameCallback:
  StreamMapEntry &e(*reinterpret_cast<MediaServerPluginRTSPServer::StreamMapEntry*>(callerId));
  if (!info || !buffer || bufferSize == 0) {
    e.env << "StreamMapEntry(" << e.id << "," << e.name.c_str() << ")::OnFrameCallback: "
             "empty frame received, calling onClose\n";
    e.onClose();
    return;
  }
  std::lock_guard<std::recursive_mutex> lock(e.registration_mutex);
  const auto r(e.registration_map.find(info));
  if (r != e.registration_map.end()) {
    if (0 == strcmp(info->getRtpPayloadFormatName(),"H264")) {
      OnH264FrameCallback(r->second,buffer,bufferSize,
                          std::chrono::duration_cast<std::chrono::microseconds>(
                            frameTime.time_since_epoch()).count());
    } else {
      r->second.callFunctions(buffer,bufferSize,
                              std::chrono::duration_cast<std::chrono::microseconds>(
                                frameTime.time_since_epoch()).count());
    }
  }
}



static
int CreateAcceptSocket(UsageEnvironment& env, Port ourPort, unsigned int bind_to_interface) {
  int accept_fd = ::socket(AF_INET,SOCK_STREAM,0);
  if (accept_fd < 0) {
    env << "MStreamPluginRtspServer CreateAcceptSocket: socket() failed: " << env.getErrno() << "\n";
    return -1;
  }
  const int yes = -1; // all bits set to 1
  if (0 != ::setsockopt(accept_fd,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char*)(&yes),sizeof(yes))) {
    env << "MStreamPluginRtspServer CreateAcceptSocket: setsockopt(SO_EXCLUSIVEADDRUSE) failed: " << env.getErrno() << "\n";
    ::closeSocket(accept_fd);
    return -1;
  }
  struct sockaddr_in sock_addr;
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.s_addr = htonl(bind_to_interface);
  sock_addr.sin_port = ourPort.num(); // already network order
  if (0 != bind(accept_fd,(struct sockaddr*)(&sock_addr),sizeof(sock_addr))) {
    env << "MStreamPluginRtspServer CreateAcceptSocket: bind("
        << ntohs(sock_addr.sin_port) << ") failed: " << env.getErrno() << "\n";
    ::closeSocket(accept_fd);
    return -1;
  }
  if (0 != ::listen(accept_fd,20)) {
    env << "MStreamPluginRtspServer CreateAcceptSocket: listen() failed: " << env.getErrno() << "\n";
    ::closeSocket(accept_fd);
    return -1;
  }
  return accept_fd;
}



MediaServerPluginRTSPServer*
MediaServerPluginRTSPServer::createNew(UsageEnvironment &env, const RTSPParameters &params, IMStreamFactory* streamManager) {
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
                                                         const RTSPParameters &params, IMStreamFactory *streamManager)
                            :RTSPServer(env, ourSocketIPv4, ourSocketIPv6, Port(params.port), NULL, 65),
                             m_HTTPServerSocket(m_HTTPServerSocket),m_HTTPsServerSocket(m_HTTPsServerSocket),
                             params(params), streamManager(streamManager),
                             m_urlPrefix(rtspURLPrefix(params.bind_to_interface ? ourSocketIPv4 : -1)) // allocated with strDup, not strdup. free with delete[]
 {
   if (!params.getUser().empty()) {
    UserAuthenticationDatabase *auth_db = new UserAuthenticationDatabase;
    auth_db->addUserRecord(params.getUser().c_str(), params.getPass().c_str());
    setAuthenticationDatabase(auth_db);
  }
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
  envir().taskScheduler().unscheduleDelayedTask(generate_info_string_task);

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

  UserAuthenticationDatabase *auth_db = setAuthenticationDatabase(nullptr);
  if (auth_db) delete auth_db;
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
  createNewClientConnectionSSL(clientSocket, clientAddr, params.getHttpCertFile().c_str(), params.getHttpKeyPath().c_str());
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

class MyFrameSource : public FramedSource, public IdContainer {
public:
  static MyFrameSource *createNew(UsageEnvironment &env,
                                  MediaServerPluginRTSPServer::StreamMapEntry &e,
                                  const SubsessionInfo *info) {
    MyFrameSource *rval = new MyFrameSource(env,e.name+","+info->getRtpPayloadFormatName());
    rval->connect(e,info);
    return rval;
  }
private:
  MyFrameSource(const MyFrameSource&);
  MyFrameSource &operator=(MyFrameSource&);
  MyFrameSource(UsageEnvironment &env,const std::string &name) : FramedSource(env),name(name) {
    env << "MyFrameSource(" << id << "," << name.c_str() << ")::MyFrameSource\n";
  }
  ~MyFrameSource(void) override {
      // I do not care from which thread this is called
    envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::~MyFrameSource start: releasing frame_registration\n";
      // release connection before cleanup so that no new framecallbacks will be deliverd
    frame_registration.reset();

      // This destructor call may come from within a frame callback.
      // The frame callback will continue after the destructor has finished and will access
      // the deleted object.

    std::lock_guard<std::mutex> lock(registered_tasks_mutex);
    if (!registered_tasks.empty()) {
      do {
        auto registered_task = registered_tasks.front();
        registered_tasks.pop_front();
        if (envir().taskScheduler().cancelCommand(registered_task)) {
          envir() << ("MyFrameSource(" + ToString(id) + "," + name + ")::~MyFrameSource: cancelled (" + std::to_string(registered_task) + ")\n").c_str();
        } else {
          envir() << ("MyFrameSource(" + ToString(id) + "," + name + ")::~MyFrameSource: cancelling (" + std::to_string(registered_task) + ") failed, "
                      "this can happen when I want to cancel my own task\n").c_str();
        }
      } while (!registered_tasks.empty());
    } else {
      envir() << ("MyFrameSource(" + ToString(id) + "," + name + ")::~MyFrameSource: no task to cancel\n").c_str();
    }
    envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::~MyFrameSource end\n";
  }
  void connect(MediaServerPluginRTSPServer::StreamMapEntry &e,
               const SubsessionInfo *info) {
    envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::connect(" << e.name.c_str() << "," << SubsessionInfoToString(*info) << ")\n";
    frame_registration = e.connect(info,
          [this](const Frame &f) {
              // called from some thread outside the plugin
//            if (f.size == 0) {
                // no more frames for this SubsessionInfo
//              envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::connect::l: empty frame received\n";
//            } else {
              std::lock_guard<std::mutex> lock(registered_tasks_mutex);
              const uint64_t registered_task = envir().taskScheduler().executeCommand(
                [this,f](uint64_t task_nr) {
                    // this is the actual frame callback.
                    // It is called from the connections UsageEnvironment thread
                  my_frame_queue.push_back(f); // Frame contains shared Ptr to data
                  const unsigned int s = my_frame_queue.size();
                  if (s >= 2*prev_frame_queue_size) {
                    prev_frame_queue_size = s;
                    if (s >= 4) {
                      envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::connect::l::l: "
                                 "frame_queue.size >= " << s << "\n";
                    }
                  }
                  {
                    std::lock_guard<std::mutex> lock(registered_tasks_mutex);
                    if (registered_tasks.front() != task_nr) abort();
                    registered_tasks.pop_front();
                    const unsigned int s = registered_tasks.size();
                    if (2*s <= prev_task_queue_size) {
                      prev_task_queue_size = s;
                      if (s >= 4) {
                        envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::connect::l::l: "
                                   "task_queue.size <= " << s << "\n";
                      }
                    }
                  }
//                  envir() << ("MyFrameSource::connect::l::l: frame in connection thread, dequeued task(" + std::to_string(task_nr) + ")\n").c_str();
                    // deliverFrame may delete MyFrameSource, then locking registered_tasks_mutex would segfault.
                  deliverFrame();
                });
//              envir() << ("MyFrameSource::connect::l: frameCb, queueing frame -> task(" + std::to_string(registered_task) + ")\n").c_str();
              registered_tasks.push_back(registered_task);
              const unsigned int s = registered_tasks.size();
              if (s >= 2*prev_task_queue_size) {
                prev_task_queue_size = s;
                if (s >= 4) {
                  envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::connect::l: "
                             "task_queue.size >= " << s << "\n";
                }
              }
//            }
          });
  }
  void deliverFrame(void) {
    if (!isCurrentlyAwaitingData()) return; // we're not ready for the data yet
    if (my_frame_queue.empty()) return;
    Frame &f(my_frame_queue.front());
    const u_int8_t *const frame_data = f.data.get();
    const unsigned int frame_size = f.size;
    if (frame_size <= 0) {
      envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::deliverFrame: handleClosure\n";
        // this will destruct MyFrameSource. Do not access *this afterwards.
      handleClosure(); // teardown
      return;
    }
    if (frame_size > fMaxSize) {
      envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::deliverFrame: frame_size(" << frame_size << ") > fMaxSize(" << fMaxSize << ")\n";
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
    const unsigned int s = my_frame_queue.size();
    if (2*s <= prev_frame_queue_size) {
      prev_frame_queue_size = s;
      if (s >= 4) {
        envir() << "MyFrameSource(" << id << "," << name.c_str() << ")::deliverFrame: "
                   "frame_queue.size <= " << s << "\n";
      }
    }
    FramedSource::afterGetting(this);
  }
  void doGetNextFrame(void) override {
    deliverFrame();
  }
  const std::string name;
  std::deque<Frame> my_frame_queue;
  std::deque<uint64_t> registered_tasks;
  std::mutex registered_tasks_mutex;
  std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry::Registration> frame_registration;
  unsigned int prev_task_queue_size = 0;
  unsigned int prev_frame_queue_size = 0;
};


class MyServerMediaSubsession : public OnDemandServerMediaSubsession, public IdContainer {
public:
  static MyServerMediaSubsession *createNew(UsageEnvironment &env,
                                            const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &entry,
                                            const SubsessionInfo *info);
  ~MyServerMediaSubsession(void) {
    envir() << "MyServerMediaSubsession(" << id;
    {
      const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> e(entry.lock());
      if (e) envir() << "," << e->name.c_str() << "," << SubsessionInfoToString(*info);
    }
    envir() << ")::~MyServerMediaSubsession\n";
  }
protected:
  MyServerMediaSubsession(UsageEnvironment &env,
                          const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &entry,
                          const SubsessionInfo *info)
    : OnDemandServerMediaSubsession(env,True), // reuseFirstSource, meaning createNewStreamSource will not be called excessively
      entry(entry),
      info(info) {
    envir() << "MyServerMediaSubsession(" << id << ")::MyServerMediaSubsession(" << entry->name.c_str() << "," << SubsessionInfoToString(*info) << ")\n";
    entry->keepAlive();
  }
  MyFrameSource *createFrameSource(unsigned clientSessionId) {
    const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> e(entry.lock());
    if (e) {
      MyFrameSource *const rval = MyFrameSource::createNew(envir(),*e,info);
      envir() << "MyServerMediaSubsession(" << id << ")::createFrameSource(" << clientSessionId
              << "): returning MyFrameSource(" << rval->id << ")\n";
      return rval;
    } else {
      envir() << "MyServerMediaSubsession(" << id << ")::createFrameSource(" << clientSessionId
              << "): the StreamMapEntry has died, returning NULL\n";
      return nullptr;
    }
  }
  const std::weak_ptr<MediaServerPluginRTSPServer::StreamMapEntry> entry;
  const SubsessionInfo *info;
};

class MyH264ServerMediaSubsession : public MyServerMediaSubsession {
public:
  MyH264ServerMediaSubsession(UsageEnvironment &env,
                              const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                              const SubsessionInfo *info)
    : MyServerMediaSubsession(env,e,info) {
  }
protected:
  const char *getAuxSDPLine(RTPSink*,FramedSource*) override {return info->getExtraInfo();}
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    FramedSource *rval = createFrameSource(clientSessionId);
    if (rval) {
      estBitrate = info->getEstBitrate(); // kbps, estimate
      rval = H264VideoStreamDiscreteFramer::createNew(envir(),rval);
    } else {
      estBitrate = 0;
    }
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *rval = nullptr;
    if (inputSource) {
      rval = H264VideoRTPSink::createNew(envir(),
                                         rtpGroupsock,
                                         rtpPayloadTypeIfDynamic);
    }
    return rval;
  }
};

class MyMpg4ServerMediaSubsession: public MyServerMediaSubsession {
public:
  MyMpg4ServerMediaSubsession(UsageEnvironment &env,
                              const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                              const SubsessionInfo *info)
    : MyServerMediaSubsession(env,e,info) {}
protected:
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    FramedSource *rval = createFrameSource(clientSessionId);
    if (rval) {
      estBitrate = info->getEstBitrate(); // kbps, estimate
      rval = MPEG4VideoStreamDiscreteFramer::createNew(envir(),rval);
    } else {
      estBitrate = 0;
    }
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *rval = nullptr;
    if (inputSource) {
      rval = MPEG4ESVideoRTPSink::createNew(envir(),
                                            rtpGroupsock,
                                            rtpPayloadTypeIfDynamic);
    }
    return rval;
  }
};

  // CAUTION: JPEGVideoSource is no FramedFilter, but I use MyJPEGVideoFramer
  // like a FramedFilter.
class MyJPEGVideoFramer : public JPEGVideoSource {
public:
  static MyJPEGVideoFramer* createNew(UsageEnvironment& env,
                                      FramedSource* inputSource) {
    return new MyJPEGVideoFramer(env,inputSource);
  }
protected:
  MyJPEGVideoFramer(UsageEnvironment& env,FramedSource* inputSource)
    : JPEGVideoSource(env),fInputSource(inputSource) {
    memset(quant_tables,0,sizeof(quant_tables));
  }
  ~MyJPEGVideoFramer(void) { // as in FramedFilter
    Medium::close(fInputSource);
  }
private:
    // implementation of virtual functions:
  void doStopGettingFrames(void) override { // as in FramedFilter
    JPEGVideoSource::doStopGettingFrames();
    if (fInputSource) fInputSource->stopGettingFrames();
  }
  void doGetNextFrame(void) override {
// who calls this function?
// fInputSource is MyFrameSource.
// This call will set
//  fInputSource->fTo = fTo;
//  fInputSource->fMaxSize = fMaxSize;
//  fInputSource->fNumTruncatedBytes = 0; // by default; could be changed by doGetNextFrame()
//  fInputSource->fDurationInMicroseconds = 0; // by default; could be changed by doGetNextFrame()
//  fInputSource->fAfterGettingFunc = afterGettingFrame
//  fInputSource->fAfterGettingClientData = this
//  fInputSource->fOnCloseFunc = FramedSource::handleClosure
//  fInputSource->fOnCloseClientData = this
//  fInputSource->fIsCurrentlyAwaitingData = True;
// and afterwards call fInputSource->doGetNextFrame()
    fInputSource->getNextFrame(fTo, fMaxSize,
                               afterGettingFrame, this,
                               FramedSource::handleClosure, this);
  }
  u_int8_t type(void) override {return fLastType;}
  u_int8_t qFactor(void) override {
      // transmit the quantisation tables with each frame:
      // this works better with mplayer
    return 255;
//    return fInputSource->getJpegQuality();
  }
  u_int8_t width(void) override {return fLastWidth;}
  u_int8_t height(void) override {return fLastHeight;}
  u_int8_t const* quantizationTables(u_int8_t& precision,
                                     u_int16_t& length) override {
    precision = 0; // 8-Bit tables
    length = 128;  // 2 tables
    return quant_tables;
  }
  u_int8_t quant_tables[128];
private:
  static void afterGettingFrame(void* clientData, unsigned frameSize,
                                unsigned numTruncatedBytes,
                                struct timeval presentationTime,
                                unsigned durationInMicroseconds) {
    MyJPEGVideoFramer* source = (MyJPEGVideoFramer*)clientData;
    source->afterGettingFrame1(frameSize, numTruncatedBytes,
                               presentationTime, durationInMicroseconds);
  }
  void afterGettingFrame1(int frameSize,
                          unsigned numTruncatedBytes,
                          struct timeval presentationTime,
                          unsigned durationInMicroseconds) {
      // RFC2435: RTP Payload Format for JPEG-compressed Video
      // requires to strip away the jpeg header, although the quantisation
      // tables may be (re-)transmitted for each frame, see RFC2435.

#define DQT 	 0xDB	// Define Quantization Table
#define SOF 	 0xC0	// Start of Frame (size information)
#define SOI 	 0xD8	// Start of Image
#define SOS 	 0xDA	// Start of Scan
      // parse jpeg
    const u_int8_t *p = fTo;
    const u_int8_t *end = fTo+frameSize;
    if (p+2 > end) return;
    if (*p++ != 0xFF) return;
    if (*p++ != SOI) return;
    for (;;) {
      if (p+4 > end) return;
      if (*p++ != 0xFF) return;
      const int marker = *p++;
      int chunk_size = (*p++) << 8;
      chunk_size |= (*p++);
      switch (marker) {
        case SOF: {
          if (p+6 > end) return;
          const u_int8_t *h = p;
          const u_int8_t precision = *h++;
          if (precision != 8) return;
          fLastHeight = ((*h++) << 5);
          fLastHeight|= ((*h++) >> 3);
          fLastWidth = ((*h++) << 5);
          fLastWidth|= ((*h++) >> 3);
          u_int8_t nr_components = *h++;
          if (nr_components > 3) return;
          for (u_int8_t i=0;i<nr_components;i++) {
            if (p+3 > end) return;
            const u_int8_t cid = *h++;
            if (cid != i+1) return;
            const u_int8_t sampling_factor = *h++;
            const u_int8_t vFactor = sampling_factor&15;
            const u_int8_t hFactor = sampling_factor>>4;
            const u_int8_t Q_table = *h++;

//   The two RTP/JPEG types currently defined are described below:
//
//                            horizontal   vertical   Quantization
//           types  component samp. fact. samp. fact. table number
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |       |  1 (Y)  |     2     |     1     |     0     |
//         | 0, 64 |  2 (U)  |     1     |     1     |     1     |
//         |       |  3 (V)  |     1     |     1     |     1     |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |       |  1 (Y)  |     2     |     2     |     0     |
//         | 1, 65 |  2 (U)  |     1     |     1     |     1     |
//         |       |  3 (V)  |     1     |     1     |     1     |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
            if (i == 0) {
              if (nr_components == 1) fLastType = 0;
              else {
                if (hFactor != 2) return;
                if (vFactor == 2) fLastType = 1; else
                if (vFactor == 1) fLastType = 0; else return;
              }
              if (Q_table != 0) return;
            } else {
              if (hFactor != 1) return;
              if (vFactor != 1) return;
              if (Q_table != 1) return;
            }
          }
        } break;
        case DQT: {
          if (p+65 > end) return;
          const u_int8_t *h = p;
          const u_int8_t qi = *h++;
          if (qi & 0xF0) return; // precision must be 0: 8bit
          if (qi > 2) return;
          memcpy(quant_tables+qi*64,h,64);
        } break;
        case SOS: {
          p += (chunk_size-2);
          if (p >= end) return;
          fFrameSize = end - p;
          memmove(fTo,p,fFrameSize);
          fNumTruncatedBytes = numTruncatedBytes;
          fPresentationTime = presentationTime;
          fDurationInMicroseconds = durationInMicroseconds;
          afterGetting(this);
        } return;
      }
      p += (chunk_size-2);
    }
  }

private:
  FramedSource* fInputSource;
  u_int8_t fLastType, fLastWidth, fLastHeight, fLastQuality;
};


class MyMJPEGServerMediaSubsession: public MyServerMediaSubsession {
public:
  MyMJPEGServerMediaSubsession(UsageEnvironment &env,
                               const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                               const SubsessionInfo *info)
    : MyServerMediaSubsession(env,e,info) {
  }
protected:
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    FramedSource *rval = createFrameSource(clientSessionId);
    if (rval) {
      estBitrate = info->getEstBitrate(); // kbps, estimate
      rval = MyJPEGVideoFramer::createNew(envir(),rval);
    } else {
      estBitrate = 0;
    }
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *rval = nullptr;
    if (inputSource) {
      rval = JPEGVideoRTPSink::createNew(envir(),
                                            rtpGroupsock);
    }
    return rval;
  }
};


static inline int HexDigitToInt(char c) {
  if ('0' <= c && c <= '9') return (c-'0');
  if ('a' <= c && c <= 'f') return (c-('a'-10));
  if ('A' <= c && c <= 'F') return (c-('A'-10));
  return -1;
}

static const int sample_frequency_index_table[16] = {
  96000,
  88200,
  64000,
  48000,
  44100,
  32000,
  24000,
  22050,
  16000,
  12000,
  11025,
  8000,
  7350,
  -1, // reserved
  -1, // reserved
  -1  // escape value
};

static const int nr_of_channel_table[16] = {
  0, // defined in GASpecificConfig
  1,
  2,
  3,
  4,
  5, // 5
  6, // 5+1
  8, // 7+1
  -1,-1,-1,-1,-1,-1,-1,-1 // reserved
};

  // returns error(<0) or how many bytes have been parsed: 2 or 5
static inline int ParseAudioSpecificConfig(const unsigned char *data,
                                           int &audio_object_type,
                                           int &sampling_frequency,
                                           int &nr_of_channels) {
  const unsigned char *dp = data;
  audio_object_type = dp[0] >> 3;
  if (audio_object_type == 31) return -1;
  const unsigned char samplingFrequencyIndex = ((dp[0]&7)<<1) | (dp[1]>>7);
  dp++;
  if (samplingFrequencyIndex == 0x0f) {
    sampling_frequency  = ((dp[0]<<1) | (dp[1]>>7));
    dp++;
    sampling_frequency <<= 8;
    sampling_frequency |= ((dp[0]<<1) | (dp[1]>>7));
    dp++;
    sampling_frequency <<= 8;
    sampling_frequency |= ((dp[0]<<1) | (dp[1]>>7));
  } else {
    sampling_frequency = sample_frequency_index_table[samplingFrequencyIndex];
  }
  const unsigned char channelConfiguration = (dp[0]>>3)&0x0f;
  dp++;
  nr_of_channels = nr_of_channel_table[channelConfiguration];
  if (sampling_frequency < 0) return -2;
  if (nr_of_channels < 0) return -3;
  return (dp - data);
}

class MyAacServerMediaSubsession : public MyServerMediaSubsession {
public:
  MyAacServerMediaSubsession(UsageEnvironment &env,
                             const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                             const SubsessionInfo *info)
      : MyServerMediaSubsession(env,e,info) {
    fmtp_config = info->getExtraInfo();
    if (!fmtp_config) {
      envir() << "MyAacServerMediaSubsession::MyAacServerMediaSubsession: initialization failed, no fmtp_config\n";
      return;
    }
    const int size = (1+strlen(fmtp_config)) / 2;

    auto audio_specific_config(std::make_unique<unsigned char[]>(std::max(5,size)));
    int i = 0;
    for (;i<size;i++) {
      const int hi = HexDigitToInt(fmtp_config[2*i]);
      const int lo = HexDigitToInt(fmtp_config[2*i+1]);
      if (hi < 0 || lo < 0) {
        envir() << "MyAacServerMediaSubsession::MyAacServerMediaSubsession: initialization failed, bad fmtp_config: \"" << fmtp_config << "\"\n";
        fmtp_config = nullptr;
        return;
      }
      audio_specific_config[i] = 16*hi + lo;
    }
    for (;i<5;i++) audio_specific_config[i] = 0;
    int audio_object_type;
    const int rc = ParseAudioSpecificConfig(audio_specific_config.get(),
                                            audio_object_type,
                                            sampling_frequency,
                                            nr_of_channels);
    if (rc < 0) {
      envir() << "MyAacServerMediaSubsession::MyAacServerMediaSubsession: initialization failed, fmtp_config: \"" << fmtp_config
              << "\" contains no valid AudioSpecificConfig: " << rc << "\n";
      fmtp_config = nullptr;
    }
  }
protected:
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    FramedSource *rval = createFrameSource(clientSessionId);
    if (rval) {
      estBitrate = info->getEstBitrate(); // kbps, estimate
    } else {
      estBitrate = 0;
    }
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *rval = nullptr;
    if (inputSource && fmtp_config) {
      rval = MPEG4GenericRTPSink::createNew(envir(),
                                            rtpGroupsock,
                                            rtpPayloadTypeIfDynamic,
                                            sampling_frequency,
                                            "audio", "AAC-hbr",
                                            fmtp_config,
                                            nr_of_channels);
    }
    return rval;
  }
private:
  const char *fmtp_config;
  int sampling_frequency,nr_of_channels;
};


class MyUnknownServerMediaSubsession : public MyServerMediaSubsession {
public:
  MyUnknownServerMediaSubsession(UsageEnvironment &env,
                                 const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                                 const SubsessionInfo *info)
    : MyServerMediaSubsession(env,e,info) {
  }
protected:
  FramedSource *createNewStreamSource(unsigned clientSessionId,
                                      unsigned &estBitrate) override {
    FramedSource *rval = createFrameSource(clientSessionId);
    if (rval) {
      estBitrate = info->getEstBitrate();
    } else {
      estBitrate = 0;
    }
    return rval;
  }
  RTPSink *createNewRTPSink(Groupsock* rtpGroupsock,
                            unsigned char rtpPayloadTypeIfDynamic,
                            FramedSource* inputSource) override {
    RTPSink *rval = nullptr;
    if (inputSource) {
      rval = SimpleRTPSink::createNew(envir(),
                                      rtpGroupsock,
                                      rtpPayloadTypeIfDynamic,
                                      info->getRtpTimestampFrequency(),
                                      info->getSdpMediaTypeString(),
                                      info->getRtpPayloadFormatName(),
                                      1,False);
    }
    return rval;
  }
};

MyServerMediaSubsession
  *MyServerMediaSubsession::createNew(UsageEnvironment &env,
                                      const std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry> &e,
                                      const SubsessionInfo *info) {
  MyServerMediaSubsession *rval = nullptr;
  if (0 == strcmp(info->getRtpPayloadFormatName(),"H264")) {
    rval = new MyH264ServerMediaSubsession(env,e,info);
  } else if (0 == strcmp(info->getRtpPayloadFormatName(),"MP4V-ES")) {
    rval = new MyMpg4ServerMediaSubsession(env,e,info);
  } else if (0 == strcmp(info->getRtpPayloadFormatName(),"JPEG")) {
    rval = new MyMJPEGServerMediaSubsession(env,e,info);
  } else if (0 == strcmp(info->getRtpPayloadFormatName(),"AAC-hbr")) {
    rval = new MyAacServerMediaSubsession(env,e,info);
  } else {
    rval = new MyUnknownServerMediaSubsession(env,e,info);
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
        completionFunc(completionFunc),completionClientData(completionClientData) {
//    env << "MediaServerPluginRTSPServer::LookupCompletionFuncData::LookupCompletionFuncData(" << streamName << ")\n";
  }
  ~LookupCompletionFuncData(void) {
//    env << "MediaServerPluginRTSPServer::LookupCompletionFuncData::~LookupCompletionFuncData(" << streamName.c_str() << ")\n";
  }
  MediaServerPluginRTSPServer *self;
  UsageEnvironment &env;
  const std::string streamName;
  lookupServerMediaSessionCompletionFunc *const completionFunc;
  void *const completionClientData;
};

std::shared_ptr<MediaServerPluginRTSPServer::StreamMapEntry>
MediaServerPluginRTSPServer::getStreamMapEntry(const std::string &stream_name) const {
  std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
  auto it(stream_map.find(stream_name));
  if (it != stream_map.end()) {
    const std::shared_ptr<StreamMapEntry> rval(it->second.lock());
    if (rval) {
      rval->env << "MediaServerPluginRTSPServer::getStreamMapEntry(" << stream_name.c_str() << "): id: " << rval->id << ", use_count: " << rval.use_count() << "\n";
    }
    return rval;
  }
  return std::shared_ptr<StreamMapEntry>();
}

void MediaServerPluginRTSPServer
::lookupServerMediaSession(UsageEnvironment &env, char const *streamName,
                           lookupServerMediaSessionCompletionFunc *completionFunc,
                           void *completionClientData,
                           Boolean isFirstLookupInSession) {
  if (!completionFunc) abort();
  if (!streamName) abort();
    // this function seems to be called for each subsession.
    // when we already have a ServerMediaSession for the first subsession,
    // return this stream, the stream of the second subsession will not work
  ServerMediaSession *sms = nullptr;
  if (!streamName[0]) {
    env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << ") begin: "
           "empty streamName\n";
  } else {
    sms = getServerMediaSession(env,streamName);
    if (sms) {
      env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << ") begin: "
             "found existing ServerMediaSession " << sms << "\n";
    } else {
        // called from the thread of the new rtsp connection (env-thread): lock recursive mutex
      const std::shared_ptr<StreamMapEntry> e(getStreamMapEntry(streamName));
      if (!e) {
        env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << ") begin: "
               "no such stream in stream_map, delegating completionFunc to stream_factory->GetStream\n";
        LookupCompletionFuncData *context = new LookupCompletionFuncData(this,env,streamName,completionFunc,completionClientData);
        streamManager->GetStream(streamName, context, false, &MediaServerPluginRTSPServer::GetStreamCb);
        env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << ") end, expecting getStreamCb\n";
        return;
      }
      env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << "): "
             "creating new ServerMediaSession with existing StreamMap entry, use_count: " << e.use_count() << "\n";
      sms = createServerMediaSession(env,e);
      env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << "): "
           "new ServerMediaSession " << sms << " with existing StreamMap entry created\n";
    }
  }
  env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << "): calling completionFunc(" << sms << ")\n";
  (*completionFunc)(completionClientData,sms);
  env << "MediaServerPluginRTSPServer::lookupServerMediaSession(" << streamName << ") end\n";
}

void MediaServerPluginRTSPServer::GetStreamCb(void *cb_context,const std::shared_ptr<IMStream> &stream) {
    // called from some thread in the executable (or from my own thread, direct callback)
  LookupCompletionFuncData *l = (LookupCompletionFuncData*)cb_context;
  if (l->env.taskScheduler().isSameThread()) {
    l->self->getStreamCb(l,stream);
  } else {
    Semaphore sem;
    l->env.taskScheduler().executeCommand(
      [l,stream,&sem](uint64_t) {
        l->self->getStreamCb(l,stream);
        sem.post();
      });
    sem.wait();
  }
  delete l;
}

void MediaServerPluginRTSPServer::getStreamCb(const MediaServerPluginRTSPServer::LookupCompletionFuncData *l,
                                              const std::shared_ptr<IMStream> &stream) {
  ServerMediaSession *sms = nullptr;
  if (stream) {
    envir() << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str() << "): start\n";
    std::shared_ptr<StreamMapEntry> e;
    {
      std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
      auto &entry(stream_map[l->streamName]);
      if (e = entry.lock()) {
        envir() << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str() << "): "
                   "existing StreamMapEntry found, new stream is not needed, creating ServerMediaSession\n";
      } else {
        e = StreamMapEntry::Create(envir(),stream,l->streamName,
          [this](const std::string &name) {
              // may be called from any thread
            envir() << "MediaServerPluginRTSPServer::getStreamCb::close-lambda(" << name.c_str() << ") start\n";
            {
                // It is not strictly necessary to erase the weak_ptr from the map.
                // This is to guard against an insane executable that does not call the callback with a NULL stream
                // when the url is wrong. In this case the map would fill up with wrong urls over time.
              std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
              stream_map.erase(name);
            }
            deleteAllServerMediaSessions(name.c_str());
              // Now the StreamMapEntry with the shared_ptr to the stream is deleted.
            envir() << "MediaServerPluginRTSPServer::getStreamCb::close-lambda(" << name.c_str() << "): end\n";
          });
        entry = e;
        envir() << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str() << "): "
                   "StreamMapEntry created, creating ServerMediaSession\n";
      }
    }
    sms = createServerMediaSession(l->env, e);
  } else {
    envir() << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str() << "): start: cannot create StreamMapEntry and ServerMediaSession"
               " because stream==NULL\n";
  }
  envir() << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str()
          << "): calling completionFunc(new ServerMediaSession " << sms << ")\n";
  (*(l->completionFunc))(l->completionClientData, sms);
  envir() << "MediaServerPluginRTSPServer::getStreamCb(" << l->streamName.c_str() << "): end\n";
}

ServerMediaSession *MediaServerPluginRTSPServer::createServerMediaSession(UsageEnvironment &env, const std::shared_ptr<StreamMapEntry> &e) {
  envir() << "MediaServerPluginRTSPServer::createServerMediaSession(" << e->name.c_str() << "): start, use_count: " << e.use_count() << "\n";
  ServerMediaSession *sms = nullptr;
  if (!e) abort();
  const SubsessionInfo *const *sl(e->getSubsessionInfoList());
  if ((sl) && (*sl)) {
    sms = ServerMediaSession::createNew(env, e->name.c_str(), "MediaServerPlugin");
    if (sms) {
      for (;*sl;sl++) {
        MyServerMediaSubsession *s = MyServerMediaSubsession::createNew(env, e, *sl);
        sms->addSubsession(s);
      }
      addServerMediaSession(sms);
    }
  }
  envir() << "MediaServerPluginRTSPServer::createServerMediaSession(" << e->name.c_str() << "): end, returning " << sms << "\n";
  return sms;
}


class LoggingUsageEnvironment : public BasicUsageEnvironment {
public:
  LoggingUsageEnvironment(TaskScheduler &scheduler,const MPluginParams &params)
    : BasicUsageEnvironment(scheduler),params(params) {}
private:
  const MPluginParams &params;
  UsageEnvironment& operator<<(char const* str) override {
    log(std::string(str?str:"(NULL)"));
    return *this;
  }
  UsageEnvironment& operator<<(int i) override {
    std::ostringstream o;
    o << i;
    log(o.str());
    return *this;
  }
  UsageEnvironment& operator<<(unsigned u) override {
    std::ostringstream o;
    o << u;
    log(o.str());
    return *this;
  }
  UsageEnvironment& operator<<(double d) override {
    std::ostringstream o;
    o << d;
    log(o.str());
    return *this;
  }
  UsageEnvironment& operator<<(void* p) override {
    std::ostringstream o;
    o << p;
    log(o.str());
    return *this;
  }
  class ThreadLogger {
    const MPluginParams &params;
    std::string content;
  public:
    ThreadLogger(const MPluginParams &params) : params(params) {}
    ~ThreadLogger(void) {
      if (!content.empty()) {
        params.log(content);
        content.clear();
      }
    }
    void log(std::string &&msg) {
      if (!msg.empty()) {
        if (content.empty()) {
          if (msg.back() == '\n') {
            params.log(msg);
          } else {
            content = msg;
          }
        } else {
          content += msg;
          if (msg.back() == '\n') {
            params.log(content);
            content.clear();
          }
        }
      }
    }
  };
  void log(std::string &&msg) {
    std::unique_ptr<ThreadLogger> &l(loggers[std::this_thread::get_id()]);
    if (!l) l = std::make_unique<ThreadLogger>(params);
    l->log(std::move(msg));
  }
  std::map<std::thread::id,std::unique_ptr<ThreadLogger> > loggers;
};

UsageEnvironment *MediaServerPluginRTSPServer::createNewUsageEnvironment(TaskScheduler &scheduler) {
  return new LoggingUsageEnvironment(scheduler,params);
}


void MediaServerPluginRTSPServer::GenerateInfoString(void *context) {
  reinterpret_cast<MediaServerPluginRTSPServer*>(context)->generateInfoString();
}

void MediaServerPluginRTSPServer::generateInfoString(void)
{
  unsigned int connections = 0;
  std::stringstream ss;
  ss << "---- RtspMStreamPlugin: url: " << m_urlPrefix.get() << "stream_name";
  if (params.httpPort)
    ss << " | RTSP-over-HTTP tunnel (Port " << params.httpPort << ")";
  else
    ss << " | no RTSP-over-HTTP tunnel";
  if (params.httpsPort)
    ss << " | RTSP-over-HTTP-over-SSL tunnel (Port " << params.httpsPort << ")";
  else
    ss << " | no RTSP-over-HTTP-over-SSL tunnel";
  ss << "\n";
  {
    std::lock_guard<std::recursive_mutex> lock(stream_map_mutex);
    for (auto &it : stream_map) {
      auto s(it.second.lock());
      if (s) connections += s->printConnections(m_urlPrefix.get()+it.first,ss);
    }
  }
  ss << "RtspMStreamPlugin Connections: " << connections << "\n";
#ifdef ALLOC_STATS
  MemAccounter::Singleton().print(ss);
  PrintAllocInfos(ss);
#endif
  ss << std::endl;
  params.status(ss.str().c_str());

  // reschedule the next status info task
  const unsigned int generate_info_string_interval = 10; //[sec]
  envir().taskScheduler().rescheduleDelayedTask(generate_info_string_task, generate_info_string_interval * 1000000ULL, GenerateInfoString, this);
}

















class RTCMediaLib {
public:
  static RTCMediaLib *Create(IMStreamFactory *streamManager,const RTSPParameters &params) {
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
  RTCMediaLib(IMStreamFactory *streamManager,const RTSPParameters &params)
    : streamManager(streamManager),params(params),
      worker_thread([this](void) {
        scheduler = BasicTaskScheduler::createNew();
        scheduler->assert_threads = true;
        env = new LoggingUsageEnvironment(*scheduler,RTCMediaLib::params);
        *env << "RTCMediaLib::RTCMediaLib::l: start\n";
        MediaServerPluginRTSPServer *server
          = MediaServerPluginRTSPServer::createNew(*env,RTCMediaLib::params,RTCMediaLib::streamManager);
        if (server) {
          *env << "RTCMediaLib::RTCMediaLib::l: running...\n";
          {
            std::lock_guard<std::mutex> lck(mtx);
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
          std::lock_guard<std::mutex> lck(mtx);
          watchVariable = 0;
          cv.notify_one();
        }
      }) {
    std::unique_lock<std::mutex> lck(mtx);
    while (watchVariable) cv.wait(lck);
  }
  bool isRunning(void) const {return scheduler;}
private:
  IMStreamFactory *const streamManager;
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
    // the library will not call the stream_factory.
extern "C" RTCMEDIALIB_API
const char *InitializeMPlugin(
              const char *interface_api_version_of_caller,
              IMStreamFactory *stream_factory,
              const MPluginParams &params) {
  OutPacketBuffer::maxSize = 4*1024*1024;
  if (0 == strcmp(interface_api_version_of_caller,rtc_media_lib_api_version)) {
      // unique_ptr so that threads will be stopped when closing the app
    static std::unique_ptr<RTCMediaLib> impl;
      // first close previous instance and free all ports
    impl = std::unique_ptr<RTCMediaLib>();
      // afterwards create new instance
    if (stream_factory) {
      impl = std::unique_ptr<RTCMediaLib>(RTCMediaLib::Create(stream_factory,static_cast<const RTSPParameters&>(params)));
      if (!impl) {
        return "Server starting failed, probably port problem. Check the log.";
      }
    }
  }
  return rtc_media_lib_api_version;
}

