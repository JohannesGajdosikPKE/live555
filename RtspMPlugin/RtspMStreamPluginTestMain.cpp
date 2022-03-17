#include "IMStream.h"

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
#include <unistd.h>
#include <sys/syscall.h>
static inline
unsigned int CurrentThreadId(void) {return syscall(SYS_gettid);}
#endif


static FILE *log_file = nullptr;

static void OnLog(void *context,const std::string &message) {
  static std::mutex m;
  std::lock_guard<std::mutex> lock(m);
  static bool log_start_of_line = true;
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
    fprintf(log_file,"%u %02u:%02u:%02u.%06u, %u: ",
            days,hours,minutes,seconds,(unsigned int)micros,
            CurrentThreadId());
    log_start_of_line = false;
  }
  fwrite(message.data(),1,message.size(),log_file);
  if (message.back() == '\n') {
    fflush(log_file);
    log_start_of_line = true;
  }
}

static
void OnStatusInfo(void *context,const std::string &message) {
}

class MySubsessionInfo : public SubsessionInfo {
public:
  virtual int generateFrame(int64_t frameTime, uint8_t *buffer, int buffer_size) = 0;
  virtual int getFrameDuration(void) const {return 40000;}
};

class SingleFilesSubsessionInfo : public MySubsessionInfo {
  int index = 0;
protected:
  virtual const char *getFileFormatTemplate(void) const = 0;
  int generateFrame(int64_t frameTime, uint8_t *buffer,int buffer_size) override {
    int rval = 0;
    for (int retries=0;retries<2;retries++) {
      char filename[128];
      sprintf(filename,getFileFormatTemplate(),index);
      FILE *f=fopen(filename,"rb");
      if (f) {
        rval = fread(buffer,1,buffer_size,f);
        fclose(f);
        index++;
        break;
      } else {
        std::cout << "fopen(" << filename << ") failed" << std::endl;
        index = 0;
      }
    }
    return rval;
  }
};

class H264SubsessionInfo : public SingleFilesSubsessionInfo {
public:
  H264SubsessionInfo(const char *aux_sdp_line) : aux_sdp_line(aux_sdp_line) {}
private:
  const char *getFileFormatTemplate(void) const override {return "../../../h264/out%06d.frame";}
  const char *getExtraInfo(void) const override {return aux_sdp_line.c_str();}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "H264";}
  std::string aux_sdp_line;
};

class Mpg4SubsessionInfo : public SingleFilesSubsessionInfo {
public:
  Mpg4SubsessionInfo(void) {}
private:
  const char *getFileFormatTemplate(void) const override {return "../../../mpg4/out%06d.frame";}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "MP4V-ES";}
};

class MJPEGSubsessionInfo : public SingleFilesSubsessionInfo {
public:
  MJPEGSubsessionInfo(void) {}
private:
  const char *getFileFormatTemplate(void) const override {return "../../../jpeg/out%06d.frame";}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "JPEG";}
};

class AacSubsessionInfo : public SingleFilesSubsessionInfo {
public:
  AacSubsessionInfo(const char *fmtp_config) : fmtp_config(fmtp_config) {}
private:
  int getFrameDuration(void) const override {return 20000;}
  const char *getFileFormatTemplate(void) const override {return "../../../aac/out%06d.frame";}
  int generateFrame(int64_t frameTime, uint8_t *buffer,int buffer_size) override {
    int rc = SingleFilesSubsessionInfo::generateFrame(frameTime,buffer,buffer_size);
    if (rc > 0) {
        // ignore arificial audiospecific config
      unsigned int ignore = 1+buffer[0];
      rc -= ignore;
      memmove(buffer,buffer+ignore,rc);
    }
    return rc;
  }
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getSdpMediaTypeString(void) const {return "audio";}
  const char *getRtpPayloadFormatName(void) const override {return "AAC-hbr";}
  const char *getExtraInfo(void) const override {return fmtp_config.c_str();}
  std::string fmtp_config;
};

class AvasysMetadataSubsessionInfo : public MySubsessionInfo {
public:
  AvasysMetadataSubsessionInfo(void) {}
  ~AvasysMetadataSubsessionInfo(void) {}
private:
  int generateFrame(int64_t frameTime, uint8_t *buffer,int buffer_size) {
    sprintf((char*)buffer,"Avasys Metadata %ld",frameTime);
    return strlen((const char*)buffer);
  }
  uint32_t getEstBitrate(void) const override {return 64;}
  uint32_t getRtpTimestampFrequency(void) const {return 90000;}
  const char *getSdpMediaTypeString(void) const {return "application";}
  const char *getRtpPayloadFormatName(void) const {return "AVASYS.METADATA";}
};

static const char *SubsessionInfoToString(const SubsessionInfo &ssi) {
  return ssi.getRtpPayloadFormatName();
}


class MyTestIMStream : public IMStream {
  std::function<void(MyTestIMStream*)> on_close;
public:
  MyTestIMStream(const char *url,std::function<void(MyTestIMStream*)> &&on_close) : on_close(on_close) {
    std::cout << "MyTestIMStream(" << this << ")::MyTestIMStream" << std::endl;

    if (0 == strcmp(url,"h264")) {
      subsession_infos[0] = new H264SubsessionInfo("");
//does not really help
//"a=fmtp:96 packetization-mode=1;profile-level-id=42C01E;sprop-parameter-sets=Z0LAHoyNQKD5APCIRqAAAAA=,aM48gAAAAA==\n"

      subsession_infos[1] =
//        this actually works, but TranscodeExport will not be able to recive it via https
//        new AvasysMetadataSubsessionInfo();
        nullptr;
      subsession_infos[2] = nullptr;
    } else if (0 == strcmp(url,"mpg4")) {
      subsession_infos[0] = new Mpg4SubsessionInfo();
      subsession_infos[1] = nullptr;
    } else if (0 == strcmp(url,"mjpeg")) {
      subsession_infos[0] = new MJPEGSubsessionInfo();
      subsession_infos[1] = nullptr;
    } else if (0 == strcmp(url,"aac")) {
      subsession_infos[0] = new AacSubsessionInfo("1210");
      subsession_infos[1] = nullptr;
    } else {
      subsession_infos[0] = nullptr;
    }
  }
  ~MyTestIMStream(void) override {
    if (on_close) {
      on_close(this);
      on_close = std::function<void(MyTestIMStream*)>();
    }
    std::cout << "MyTestIMStream(" << this << ")::~MyTestIMStream" << std::endl;
    for (const MySubsessionInfo *const*s=subsession_infos;*s;s++) delete *s;
  }
  bool isInitialized(void) const {return subsession_infos[0];}
  int64_t step(int64_t now) {
//    std::cout << "MyTestIMStream(" << this << ")::step" << std::endl;
    std::lock_guard<std::mutex> lock(internal_mutex);
    const int buffer_size = 64*1024;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(buffer_size);
    int wait_duration = 10000000;
    for (MySubsessionInfo *const*s=subsession_infos;*s;s++) {
      const int frame_duration = (*s)->getFrameDuration();
      if (wait_duration > frame_duration) wait_duration = frame_duration;
      const int size = (*s)->generateFrame(now,buffer.get(),buffer_size);
      for (auto &it : frame_cb_map) it.second(it.first,*s,buffer.get(),size,
                                              TimeType(std::chrono::microseconds(now)));
    }
    return wait_duration;
  }
  void lastEmptyStep(void) {
    std::lock_guard<std::mutex> lock(internal_mutex);
    for (auto &it : frame_cb_map) it.second(it.first,nullptr,nullptr,0,TimeType());
  }
private:
    // the SubsessionInfos live on the heap of the executable at the same address
    // at least as long as the IMStream lives, last pointer in the array is 0.
    // This information is used for generating the RTSP response
    // and shall stay constant until the stream is closed
  const SubsessionInfo *const *getSubsessionInfoList(void) const override {
    return (const SubsessionInfo *const *)subsession_infos;
  }
  std::mutex internal_mutex;

  typedef std::map<void*,TOnFrameCallbackPtr> OnFrameCallbackMap;
  OnFrameCallbackMap frame_cb_map;

   // register for frames of the given subsession and associate the Subsession with the callerId.
    // After onFrameCallback(size==0) is called, no more frames for this Subsession will be received
    // until RegisterOnFrame is called again
  void RegisterOnFrame(void *callerId, TOnFrameCallbackPtr onFrameCallback) override {
    std::lock_guard<std::mutex> lock(internal_mutex);
    if (onFrameCallback) {
      std::cout << "MyTestIMStream::RegisterOnFrame: register" << std::endl;
      frame_cb_map[callerId] = onFrameCallback;
    } else {
      std::cout << "MyTestIMStream::RegisterOnFrame: unregister" << std::endl;
      frame_cb_map.erase(callerId);
    }
  }
private:
  MySubsessionInfo *subsession_infos[8];
};

class MyIMStreamFactory : public IMStreamFactory {
  std::atomic<bool> continue_loop;
  std::set<MyTestIMStream*> stream_set;
  std::mutex stream_set_mutex;
public:
  MyIMStreamFactory(void) : continue_loop(true) {}
  void run(void) {
    std::cout << "Press Enter to quit..." << std::endl;
    std::thread th([this]() {
      std::string answer;
      std::getline(std::cin,answer);
      std::cout << "Enter pressed, setting stop flag" << std::endl;
      continue_loop = false;
    });
    while (continue_loop) {
    const unsigned long now = 
      std::chrono::duration_cast<std::chrono::microseconds>
        (std::chrono::system_clock::now().time_since_epoch()).count();
      int64_t wait_duration = 10000000;
      {
        std::lock_guard<std::mutex> lock(stream_set_mutex);
        for (auto &it : stream_set) {
          const int64_t rc = it->step(now);
          if (wait_duration > rc) wait_duration = rc;
        }
      }
      std::this_thread::sleep_for(std::chrono::microseconds(wait_duration));
    }
    {
      std::lock_guard<std::mutex> lock(stream_set_mutex);
      for (auto &it : stream_set) it->lastEmptyStep();
    }
    th.join();
  }
  ~MyIMStreamFactory(void) {
  }
private:
  void GetStream(const char *url,void *context,GetStreamCb *cb) override {
    std::cout << "MyIMStreamFactory::GetStream(" << url << ')' << std::endl;
    MyTestIMStream *rval(new MyTestIMStream(url,
                             [this](MyTestIMStream *self) {
                               std::lock_guard<std::mutex> lock(stream_set_mutex);
                               stream_set.erase(self);
                             }));
    if (rval->isInitialized()) {
      {
        std::lock_guard<std::mutex> lock(stream_set_mutex);
        stream_set.insert(rval);
      }
      (*cb)(context,TStreamPtr(rval));
    } else {
      delete rval;
      (*cb)(context,TStreamPtr());
    }
  }
};



static const char *const exe_api_version = RTCMEDIALIB_API_VERSION;


int main(int argc,char *argv[]) {
  log_file = fopen((std::string(argv[0])+".log").c_str(),"w");
  {
    MyIMStreamFactory factory;
    RTSPParameters params(&OnLog,nullptr,
                          &OnStatusInfo,nullptr,
                          2554,8880,8881,0,
                          false,true,
                          "C:\\Users\\01jga728\\zertifikat-pub.pem",
                          "C:\\Users\\01jga728\\zertifikat-key.pem",
                          "","");
    const char *const lib_api_version
      = InitializeMPlugin(exe_api_version,&factory,params);
    std::cout << "my api version: " << exe_api_version
              << ", plugin api version: " << lib_api_version << std::endl;
    if (0 == strcmp(exe_api_version,lib_api_version)) {
      factory.run();
    }
    std::cout << "deinitializing plugin" << std::endl;
    InitializeMPlugin(exe_api_version,nullptr,params);
    std::cout << "destroing factory" << std::endl;
  }
  std::cout << "closing logfile" << std::endl;
  fclose(log_file);
  std::cout << "bye." << std::endl;
  return 0;
}
