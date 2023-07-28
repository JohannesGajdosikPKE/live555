#include "IMStream.h"

using namespace InterfaceMediaStream;

#include <string>
#include <map>
#include <list>
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
#include <dirent.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>
static inline
unsigned int CurrentThreadId(void) {return syscall(SYS_gettid);}
#endif

class DynamicLibrary {
public:
  DynamicLibrary(const char *filename) {
    handle =
#ifdef _WIN32
      (void*)LoadLibraryA(filename);
#else
      dlopen(filename,RTLD_NOW|RTLD_GLOBAL);
    if (!handle) {
      std::cout << "DynamicLibrary::DynamicLibrary(" << filename << "): "
                   "dlopen failed: " << dlerror() << std::endl;
    }
#endif
  }
  ~DynamicLibrary(void) {
    if (handle)
#ifdef _WIN32
      FreeLibrary((HMODULE)handle);
#else
      dlclose(handle);
#endif
  }
  void *getAddr(const char *symbol) {
    return
#ifdef _WIN32
      (void*)GetProcAddress((HMODULE)handle,symbol);
#else
      dlsym(handle,symbol);
#endif
  }
  bool isInitialized(void) const {return handle;}
private:
  void *handle;
};

static const char *prog_name = nullptr;
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
  FILE *f = fopen((std::string(prog_name)+".status").c_str(),"w");
  if (f) {
    fwrite(message.data(),1,message.size(),f);
    fclose(f);
  }
}

class MySubsessionInfo : public SubsessionInfo {
public:
  virtual int generateFrame(int64_t frameTime, uint8_t *buffer, int buffer_size) = 0;
  virtual int getFrameDuration(void) const {return 40000;}
};

class SingleFilesSubsessionInfo : public MySubsessionInfo {
  std::list<std::string> file_list;
  std::list<std::string>::iterator file_it;
protected:
  SingleFilesSubsessionInfo(void) : file_it(file_list.end()) {}
  virtual const char *getDirName(void) const = 0;
  int generateFrame(int64_t frameTime, uint8_t *buffer,int buffer_size) override {
    if (file_list.empty()) {
      std::string dir_name(getDirName());
      if (dir_name.empty()) {
        return 0;
      }
#ifdef _WIN32
      if (dir_name.back() != '\\') dir_name.push_back('\\');
      HANDLE hFind;
      WIN32_FIND_DATA FindFileData;
      if ((hFind = FindFirstFile((dir_name+"*").c_str(), &FindFileData)) == INVALID_HANDLE_VALUE) {
        std::cout << "FindFirstFile(" << dir_name << "*) failed" << std::endl;
        return 0;
      } else {
        std::cout << "FindFirstFile(" << dir_name << "*) ok" << std::endl;
        do {
          if (FindFileData.cFileName[0] != '.') file_list.push_back(dir_name + FindFileData.cFileName);
        } while (FindNextFile(hFind, &FindFileData));
        FindClose(hFind);
      }
#else
      if (dir_name.back() != '/') dir_name.push_back('/');
      DIR *dp = opendir(dir_name.c_str());
      struct dirent *e;
      if (!dp) {
        std::cout << "opendir(" << dir_name << ") failed" << std::endl;
        return 0;
      }
      std::cout << "opendir(" << dir_name << ") ok" << std::endl;
      while ( (e = readdir(dp)) ) {
        if (e->d_name[0] != '.') file_list.push_back(dir_name + e->d_name);
      }
      closedir(dp);
#endif
      if (file_list.empty()) return 0;
      file_list.sort();
      file_it == file_list.end();
      std::cout << "opendir(" << dir_name << ") ok, files: " << file_list.size() << std::endl;
    }
    for (int retries = file_list.size();retries>0;retries--) {
      if (file_it == file_list.end()) {file_it = file_list.begin();}
      else {++file_it;}
      if (file_it == file_list.end()) break;
      FILE *f = fopen(file_it->c_str(),"rb");
      if (f) {
        const int rval = fread(buffer,1,buffer_size,f);
        fclose(f);
        if (rval > 0) return rval;
      }
    }
    return 0;
  }
};

class H264SubsessionInfo : public SingleFilesSubsessionInfo {
public:
  H264SubsessionInfo(const char *aux_sdp_line) : aux_sdp_line(aux_sdp_line) {}
private:
  const char *getDirName(void) const override {return "h264";}
  const char *getExtraInfo(void) const override {return aux_sdp_line.c_str();}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "H264";}
  std::string aux_sdp_line;
};

class H265SubsessionInfo : public SingleFilesSubsessionInfo {
public:
  H265SubsessionInfo(const char *aux_sdp_line) : aux_sdp_line(aux_sdp_line) {}
private:
  const char *getDirName(void) const override {return "h265";}
  const char *getExtraInfo(void) const override {return aux_sdp_line.c_str();}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "H265";}
  std::string aux_sdp_line;
};

class Mpg4SubsessionInfo : public SingleFilesSubsessionInfo {
public:
  Mpg4SubsessionInfo(void) {}
private:
  const char *getDirName(void) const override {return "mpg4";}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "MP4V-ES";}
};

class MJPEGSubsessionInfo : public SingleFilesSubsessionInfo {
public:
  MJPEGSubsessionInfo(void) {}
private:
  const char *getDirName(void) const override {return "jpeg";}
  uint32_t getEstBitrate(void) const override {return 2000;}
  const char *getRtpPayloadFormatName(void) const override {return "JPEG";}
};

class AacSubsessionInfo : public SingleFilesSubsessionInfo {
public:
  AacSubsessionInfo(const char *fmtp_config) : fmtp_config(fmtp_config) {}
private:
  int getFrameDuration(void) const override {return 20000;}
  const char *getDirName(void) const override {return "../../../aac";}
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
    } else if (0 == strcmp(url,"h265")) {
      subsession_infos[0] = new H265SubsessionInfo("");
      subsession_infos[1] = nullptr;
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
    const int buffer_size = 1024*1024;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(buffer_size);
    int wait_duration = 10000000;
    for (MySubsessionInfo *const*s=subsession_infos;*s;s++) {
      const int frame_duration = (*s)->getFrameDuration();
      if (wait_duration > frame_duration) wait_duration = frame_duration;
      const int size = (*s)->generateFrame(now,buffer.get(),buffer_size);
      if (size > 0) {
        for (auto &it : frame_cb_map) it.second(it.first,*s,buffer.get(),size,
                                                TimeType(std::chrono::microseconds(now)));
      } 
    }
    return wait_duration;
  }
  void lastEmptyStep(void) {
    OnFrameCallbackMap tmp;
    {
      std::lock_guard<std::mutex> lock(internal_mutex);
      tmp.swap(frame_cb_map);
    }
    for (auto &it : tmp) it.second(it.first,nullptr,nullptr,0,TimeType());
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
      int64_t wait_duration = 1000000000;
      {
        std::lock_guard<std::mutex> lock(stream_set_mutex);
        for (auto &it : stream_set) {
          const int64_t rc = it->step(now);
          if (wait_duration > rc) wait_duration = rc;
        }
      }
      if (wait_duration >= 1000000000) wait_duration = 20000;
      std::this_thread::sleep_for(std::chrono::microseconds(wait_duration));
    }
    std::cout << "joining" << std::endl;
    th.join();
    {
      std::cout << "sending last empty frame" << std::endl;
      std::set<MyTestIMStream*> tmp_set;
      {
        std::lock_guard<std::mutex> lock(stream_set_mutex);
        tmp_set.swap(stream_set);
      }
      for (auto &it : tmp_set) it->lastEmptyStep();
      std::cout << "frame sent" << std::endl;
    }
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
      std::lock_guard<std::mutex> lock(stream_set_mutex);
      stream_set.insert(rval);
        // no framefallback before (*cb) has been called.
	// Therefore stream_set_mutex must stay locked.
      (*cb)(context,TStreamPtr(rval));
    } else {
      delete rval;
      (*cb)(context,TStreamPtr());
    }
  }
};



static const char *const exe_api_version = RTCMEDIALIB_API_VERSION;

static const char *const plugin_name =
#ifdef _WIN32
  "RtspMStreamPlugin"
  #ifdef _DEBUG
    "d"
  #endif
  ".dll"
#else
  "./libRtspMStreamPlugin"
  #ifdef _DEBUG
    "d"
  #endif
  ".so"
#endif
;
static const char *const init_function_name = "InitializeMPlugin";



static void PrintUsage(void) {
  std::cout << "Usage: " << prog_name << " [--rtsp <port>] [--rtsps <port>] [--http <port>] [--https <port>]"
                                         " [--cert_file <cert_file> --key_file <key_file>]"
            << std::endl;
}


int main(int argc,char **argv) {
  prog_name = *argv++;
  log_file = fopen((std::string(prog_name)+".log").c_str(),"w");
  const char *cert_file = 0;
  const char *key_file = 0;
  int rtsp = 0;
  int rtsps = 0;
  int http = 0;
  int https = 0;
  while (*argv) {
    if (0 == strcmp("--help",*argv) || 0 == strcmp("-h",*argv)) {
      PrintUsage();
      return 1;
    } else if (0 == strcmp("--cert_file",*argv)) {
      if (!*++argv) {
        std::cout << "cert_file expected" << std::endl;
        return 1;
      }
      if (cert_file) {
        std::cout << "cert_file given twice" << std::endl;
        return 1;
      }
      cert_file = *argv++;
    } else if (0 == strcmp("--key_file",*argv)) {
      if (!*++argv) {
        std::cout << "key_file expected" << std::endl;
        return 1;
      }
      if (key_file) {
        std::cout << "key_file given twice" << std::endl;
        return 1;
      }
      key_file = *argv++;
    } else if (0 == strcmp("--rtsp",*argv)) {
      if (!*++argv) {
        std::cout << "rtsp port expected" << std::endl;
        return 1;
      }
      if (rtsp) {
        std::cout << "rtsp port given twice" << std::endl;
        return 1;
      }
      if (1 != sscanf(*argv,"%d",&rtsp) || rtsp <= 0 || rtsp > 0xFFFF) {
        std::cout << "bad rtsp port: \"" << *argv << '"' << std::endl;
        return 1;
      }
      argv++;
    } else if (0 == strcmp("--rtsps",*argv)) {
      if (!*++argv) {
        std::cout << "rtsps port expected" << std::endl;
        return 1;
      }
      if (rtsps) {
        std::cout << "rtsps port given twice" << std::endl;
        return 1;
      }
      if (1 != sscanf(*argv,"%d",&rtsps) || rtsps <= 0 || rtsps > 0xFFFF) {
        std::cout << "bad rtsps port: \"" << *argv << '"' << std::endl;
        return 1;
      }
      argv++;
    } else if (0 == strcmp("--http",*argv)) {
      if (!*++argv) {
        std::cout << "http port expected" << std::endl;
        return 1;
      }
      if (http) {
        std::cout << "http port given twice" << std::endl;
        return 1;
      }
      if (1 != sscanf(*argv,"%d",&http) || http <= 0 || http > 0xFFFF) {
        std::cout << "bad http port: \"" << *argv << '"' << std::endl;
        return 1;
      }
      argv++;
    } else if (0 == strcmp("--https",*argv)) {
      if (!*++argv) {
        std::cout << "https port expected" << std::endl;
        return 1;
      }
      if (https) {
        std::cout << "https port given twice" << std::endl;
        return 1;
      }
      if (1 != sscanf(*argv,"%d",&https) || https <= 0 || https > 0xFFFF) {
        std::cout << "bad https port: \"" << *argv << '"' << std::endl;
        return 1;
      }
      argv++;
    } else {
      std::cout << "unknown commandline argument: \"" << *argv << '"' << std::endl;
      PrintUsage();
      return 1;
    }
  }
  if (rtsp == 0 && rtsps == 0 && http == 0 && https == 0) {
    std::cout << "no ports specified" << std::endl;
    PrintUsage();
    return 1;
  }
  if (!cert_file) cert_file = "";
  if (!key_file) key_file = "";
  {
    DynamicLibrary plugin(plugin_name);
    if (!plugin.isInitialized()) {
      std::cout << "Could not load plugin " << plugin_name << std::endl;
    } else {
      MyIMStreamFactory factory;
      InitializeMPluginFunc *const init_function
        = (InitializeMPluginFunc*)plugin.getAddr(init_function_name);
      if (!init_function) {
        std::cout << "Could not get symbol \"" << init_function_name
                  << "\" from plugin " << plugin_name << std::endl;
      } else {
        RTSPParameters params(&OnLog,nullptr,
                              &OnStatusInfo,nullptr,
                              rtsp,http,https,rtsps,
                              0,0,0,0,
                              false,false,false,false,
                              false,false,false,false,
                              cert_file,
                              key_file);
//        params.setUserPass("User1","Pass1");
//        params.setUserPass("User2","Pass2");
        const char *const lib_api_version
          = (*init_function)(exe_api_version,&factory,params);
        std::cout << "my api version: " << exe_api_version
                  << ", plugin api version: " << lib_api_version << std::endl;
        if (0 == strcmp(exe_api_version,lib_api_version)) {
          factory.run();
          std::cout << "deinitializing plugin" << std::endl;
          (*init_function)(exe_api_version,nullptr,params);
        }
      }
      std::cout << "destroying factory" << std::endl;
    }
  }
  std::cout << "closing logfile" << std::endl;
  fclose(log_file);
  std::cout << "bye." << std::endl;
  return 0;
}
