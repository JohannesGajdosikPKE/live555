#include "IRTC.h"

#include <string>
#include <map>
#include <set>
#include <iostream>
#include <mutex>
#include <functional>
#include <atomic>
#include <chrono>
#include <thread>

#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
static inline
unsigned int CurrentThreadId(void) {return GetCurrentThreadId();}
#else
static inline
unsigned int CurrentThreadId(void) {return gettid();}
#endif

class MySubsessionInfo : public SubsessionInfo {
public:
  virtual int generateFrame(int64_t frameTime, uint8_t *buffer, int buffer_size) = 0;
};

class H264SubsessionInfo : public MySubsessionInfo {
public:
  H264SubsessionInfo(const char *aux_sdp_line) : aux_sdp_line(aux_sdp_line) {}
  ~H264SubsessionInfo(void) {}
private:
  int index = 0;
  int generateFrame(int64_t frameTime, uint8_t *buffer,int buffer_size) {
    int rval = 0;
    char filename[128];
    sprintf(filename,"../out%06d.frame",index);
    if (++index > 99) index = 0;
    FILE *f=fopen(filename,"rb");
    if (f) {
      rval = fread(buffer,1,buffer_size,f);
      fclose(f);
    } else {
      std::cout << "fopen(" << filename << ") failed" << std::endl;
    }
    return rval;
  }
  const char *getAuxSdpLine(void) const override {return aux_sdp_line.c_str();}
  RTCFormat GetFormat(void) const override {return RTCFormatH264;}
  uint32_t getEstBitrate(void) const override {return 2000;}
  std::string aux_sdp_line;
};

class AvasysMetadataSubsessionInfo : public MySubsessionInfo {
public:
  AvasysMetadataSubsessionInfo(void) {}
  ~AvasysMetadataSubsessionInfo(void) {}
private:
  int generateFrame(int64_t frameTime, uint8_t *buffer,int buffer_size) {
    sprintf((char*)buffer,"Avasys Metadata %lld",frameTime);
    return strlen((const char*)buffer);
  }
  RTCFormat GetFormat(void) const override {return RTCFormatUnknown;}
  uint32_t getEstBitrate(void) const override {return 64;}
  uint32_t getRtpTimestampFrequency(void) const {return 90000;}
  const char *getSdpMediaTypeString(void) const {return "application";}
  const char *getRtpPayloadFormatName(void) const {return "AVASYS.METADATA";}
};

static const char *SubsessionInfoToString(const SubsessionInfo &ssi) {
  switch (ssi.GetFormat()) {
    case RTCFormatJPEG : return "JPEG";
    case RTCFormatH264 : return "H264";
    case RTCFormatYUVI420: return "YUVI420";
    case RTCFormatUnknown: return ssi.getRtpPayloadFormatName();
  }
  return "undefined_format_value";
}


class MyTestIRTCStream : public IRTCStream {
  std::function<void(MyTestIRTCStream*)> on_close;
public:
  MyTestIRTCStream(std::function<void(MyTestIRTCStream*)> &&on_close) : on_close(on_close) {
    std::cout << "MyTestIRTCStream(" << this << ")::MyTestIRTCStream" << std::endl;
    subsession_infos[0] = new H264SubsessionInfo(
""
//does not really help
//"a=fmtp:96 packetization-mode=1;profile-level-id=42C01E;sprop-parameter-sets=Z0LAHoyNQKD5APCIRqAAAAA=,aM48gAAAAA==\n"
);
    subsession_infos[1] =
//      this actually works, but TranscodeExport will not be able to recive it via https
//      new AvasysMetadataSubsessionInfo();
      nullptr;
    subsession_infos[2] = nullptr;
  }
  ~MyTestIRTCStream(void) override {
    if (on_close) {
      on_close(this);
      on_close = std::function<void(MyTestIRTCStream*)>();
    }
    std::cout << "MyTestIRTCStream(" << this << ")::~MyTestIRTCStream" << std::endl;
    for (const MySubsessionInfo *const*s=subsession_infos;*s;s++) delete *s;
  }
  int64_t step(int64_t now) {
//    std::cout << "MyTestIRTCStream(" << this << ")::step" << std::endl;
    std::lock_guard<std::mutex> lock(internal_mutex);
    const int buffer_size = 64*1024;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(buffer_size);
    for (MySubsessionInfo *const*s=subsession_infos;*s;s++) {
      const int size = (*s)->generateFrame(now,buffer.get(),buffer_size);
      for (auto &it : subsession_cb_map) it.second(it.first,*s,buffer.get(),size,now);
    }
    return 40000;
  }
private:
    // the SubsessionInfos live on the heap of the executable at the same address
    // at least as long as the IRTCStream lives, last pointer in the array is 0.
    // This information is used for generating the RTSP response
    // and shall stay constant until the stream is closed
  const SubsessionInfo *const *getSubsessionInfoList(void) const override {
    return (const SubsessionInfo *const *)subsession_infos;
  }
  std::mutex internal_mutex;

  typedef std::map<void*,TOnFrameCallbackPtr> OnFrameCallbackMap;
  OnFrameCallbackMap subsession_cb_map;

   // register for frames of the given subsession and associate the Subsession with the callerId.
    // After onFrameCallback(size==0) is called, no more frames for this Subsession will be received
    // until RegisterOnFrame is called again
  void RegisterOnFrame(void *callerId, TOnFrameCallbackPtr onFrameCallback) override {
    std::lock_guard<std::mutex> lock(internal_mutex);
    if (onFrameCallback) {
      std::cout << "MyTestIRTCStream::RegisterOnFrame: register" << std::endl;
      subsession_cb_map[callerId] = onFrameCallback;
    } else {
      std::cout << "MyTestIRTCStream::RegisterOnFrame: unregister" << std::endl;
      subsession_cb_map.erase(callerId);
    }
  }
private:
  MySubsessionInfo *subsession_infos[8];
};

class MyIRTCStreamFactory : public IRTCStreamFactory {
  std::atomic<bool> continue_loop = true;
  std::set<MyTestIRTCStream*> stream_set;
  std::mutex stream_set_mutex;
public:
  MyIRTCStreamFactory(void) {}
  void run(void) {
    std::cout << "Press Enter to quit..." << std::endl;
    std::thread th([this]() {
      std::string answer;
      std::getline(std::cin,answer);
      std::cout << "Answer: \"" << answer << '"' << std::endl;
      continue_loop = false;
    });
    while (continue_loop) {
    const unsigned long now = 
      std::chrono::duration_cast<std::chrono::microseconds>
        (std::chrono::system_clock::now().time_since_epoch()).count();
      {
        std::lock_guard<std::mutex> lock(stream_set_mutex);
        for (auto &it : stream_set) it->step(now);
      }
      std::this_thread::sleep_for(std::chrono::microseconds(40000));
    }
    th.join();
  }
private:
  void GetStream(const char *url,void *context,GetStreamCb *cb) override {
    std::cout << "MyIRTCStreamFactory::GetStream(" << url << ')' << std::endl;
    MyTestIRTCStream *rval(new MyTestIRTCStream(
                             [this](MyTestIRTCStream *self) {
                               std::lock_guard<std::mutex> lock(stream_set_mutex);
                               stream_set.erase(self);
                             }));
    {
      std::lock_guard<std::mutex> lock(stream_set_mutex);
      stream_set.insert(rval);
    }
    (*cb)(context,TStreamPtr(rval));
  }
  void OnStatsInfo(const std::string &statsInfo) override {
    std::cout << "\nOnStatsInfo:\n" << statsInfo << std::endl;
  }
  void OnLog(const std::string &message) {
    static std::mutex m;
    std::lock_guard<std::mutex> lock(m);
    static bool log_start_of_line = true;
    static FILE *f=fopen("out.log","w");
    if (log_start_of_line) {
      uint64_t micros
        = std::chrono::duration_cast<std::chrono::microseconds>
            (std::chrono::system_clock::now().time_since_epoch()).count();
      const unsigned int days = micros / (24*60*60*1000000ULL);
      micros -= days * (24*60*60*1000000ULL);
      const unsigned int hours = micros /   (60*60*1000000ULL);
      micros -= hours *   (60*60*1000000ULL);
      const unsigned int minutes = micros /    (60*1000000ULL);
      micros -= minutes *    (60*1000000ULL);
      const unsigned int seconds = micros /        1000000ULL;
      micros -= seconds *        1000000ULL;
      fprintf(f,"%u %02u:%02u:%02u.%06u, %u: ",
              days,hours,minutes,seconds,(unsigned int)micros,
              CurrentThreadId());
      log_start_of_line = false;
    }
    fwrite(message.data(),1,message.size(),f);
    if (message.back() == '\n') {
      fflush(f);
      log_start_of_line = true;
    }
  }
};



static const char *const exe_api_version = RTCMEDIALIB_API_VERSION;


int main(int argc,char *argv[]) {
  MyIRTCStreamFactory factory;
  RTSPParameters params(554,8080,8081,0,
                        "C:\\Users\\01jga728\\zertifikat-pub.pem",
                        "C:\\Users\\01jga728\\zertifikat-key.pem"
);
  const char *const lib_api_version
    = initializeRTCMediaLib(exe_api_version,&factory,params);
  std::cout << "my api version: " << exe_api_version
            << ", plugin api version: " << lib_api_version << std::endl;
  if (0 == strcmp(exe_api_version,lib_api_version)) {
    factory.run();
  }
  return 0;
}