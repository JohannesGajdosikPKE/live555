#ifndef IM_STREAM_H_
#define IM_STREAM_H_

#include <string>
#include <memory>
#include <chrono>

namespace InterfaceMediaStream {

class SubsessionInfo {
public:
  virtual ~SubsessionInfo(void) {}

    // used for creation of FramedSource, will show up in the SDP description
  virtual uint32_t getEstBitrate(void) const {return 0;}

    // currently supported: H264, MP4V-ES, JPEG, AAC-hbr.
    // all others will result in a SimpleRTPSink with the given
    // RtpTimestampFrequency, SdpMediaTypeString and RtpPayloadFormatName
  virtual const char *getRtpPayloadFormatName(void) const = 0;
  virtual uint32_t getRtpTimestampFrequency(void) const {return 0;}
  virtual const char *getSdpMediaTypeString(void) const {return nullptr;}
  virtual uint32_t getInitialRtpTimestamp(void) const { return 0;}
  virtual bool useRTPTimestampCorrection(void) const { return false; }

    // payload specific extra information
    // like AuxSdpLine in case of H264 or FmtpConfig in case of AAC-hbr
  virtual const char *getExtraInfo(void) const {return nullptr;}

protected:
  SubsessionInfo(void) {}
private:
  SubsessionInfo(const SubsessionInfo&);
  SubsessionInfo &operator=(const SubsessionInfo&);
};

typedef std::chrono::duration<int64_t,std::micro> DurationType;

struct TimeType
{
  TimeType(void) {}
  template<class T> TimeType(const T &t) : abs_time(t) {}
  template<class T> TimeType(const T &t, const std::uint32_t& rtime, const std::uint32_t& rfreq, const std::uint32_t& rid)
    : abs_time(t),rtp_time(rtime), rtp_freq(rfreq), rtp_id(rid) {}

  std::chrono::time_point<std::chrono::system_clock, DurationType> abs_time;
  std::uint32_t rtp_time = 0;
  std::uint32_t rtp_freq = 0;
  std::uint32_t rtp_id = 0; 
};

typedef void (*TOnFrameCallbackPtr)(void *callerId, const SubsessionInfo *info,
                                    const uint8_t *buffer, int bufferSize,
                                    const TimeType &frameTime);

class IMStream {
public:
  virtual ~IMStream(void) {}

    // the SubsessionInfos live on the heap of the executable at the same address
    // at least as long as the IMStream lives, last pointer in the array is 0.
    // This information is used for generating the RTSP response
    // and shall stay constant until the stream is closed
  virtual const SubsessionInfo *const *getSubsessionInfoList(void) const = 0;

    // register for frames with the callerId. Can be called many times, the new callback will replace the old one.
    // After the callback is changed, the old callback receives no more frames.
    // The new value can be NULL.
    // After onFrameCallback(callerId,NULL) is called, no more frames will be received
    // until RegisterOnFrame is called again.
  virtual void RegisterOnFrame(void *callerId, TOnFrameCallbackPtr onFrameCallback) = 0;

};

typedef std::shared_ptr<IMStream> TStreamPtr;

class IMStreamFactory
{
public:
  virtual ~IMStreamFactory(void) {}
  typedef void (GetStreamCb)(void *context,const TStreamPtr &stream);
  virtual void GetStream(const char *url, void *context, GetStreamCb *cb) = 0;
};


class MPluginParams {
public:
  typedef void (*LogCallbackPtr)(void *context, const std::string &message);
  typedef void (*StatusCallbackPtr)(void *context, const std::string &message);
  MPluginParams(void) {}
  MPluginParams(LogCallbackPtr log_cb,void *log_cb_context,
                StatusCallbackPtr status_cb,void *status_cb_context)
    :log_cb(log_cb),log_cb_context(log_cb_context),
     status_cb(status_cb),status_cb_context(status_cb_context) {
    if (!log_cb) abort();
    if (!status_cb) abort();
  }
  void log(const std::string &message) const {log_cb(log_cb_context,message);}
  void status(const std::string &message) const {status_cb(status_cb_context,message);}
  LogCallbackPtr log_cb = nullptr;
  void *log_cb_context = nullptr;
  StatusCallbackPtr status_cb = nullptr;
  void *status_cb_context = nullptr;
};

class RTSPParameters : public MPluginParams {
public:
  RTSPParameters(void) {}
  RTSPParameters(LogCallbackPtr log_cb,void *log_cb_context,
                 StatusCallbackPtr status_cb,void *status_cb_context,
                 uint16_t rtspPort,uint16_t httpPort,
                 uint16_t httpsPort,uint16_t rtspsPort,
                 uint32_t bind_to_interface_rtsp,uint32_t bind_to_interface_http,
                 uint32_t bind_to_interface_https,uint32_t bind_to_interface_rtsps,
                 bool use_ipv6_rtsp,bool use_ipv6_http,bool use_ipv6_https,bool use_ipv6_rtsps,
                 bool rtsp_is_optional,bool http_is_optional,bool https_is_optional,bool rtsps_is_optional,
                 const std::string &tls_cert_file,const std::string &tls_key_file)
    : MPluginParams(log_cb,log_cb_context,status_cb,status_cb_context),
      rtspPort(rtspPort),httpPort(httpPort),httpsPort(httpsPort),rtspsPort(rtspsPort),
      bind_to_interface_rtsp(bind_to_interface_rtsp),
      bind_to_interface_http(bind_to_interface_http),
      bind_to_interface_https(bind_to_interface_https),
      bind_to_interface_rtsps(bind_to_interface_rtsps),
      use_ipv6_rtsp(use_ipv6_rtsp),
      use_ipv6_http(use_ipv6_http),
      use_ipv6_https(use_ipv6_https),
      use_ipv6_rtsps(use_ipv6_rtsps),
      rtsp_is_optional(rtsp_is_optional),
      http_is_optional(http_is_optional),
      https_is_optional(https_is_optional),
      rtsps_is_optional(rtsps_is_optional),
      tls_cert_file(tls_cert_file),tls_key_file(tls_key_file) {}
  const std::string &getTlsCertFile(void) const {return tls_cert_file;}
  const std::string &getTlsKeyFile(void) const {return tls_key_file;}
  class UserPassIterator {
  public:
    UserPassIterator(const std::string *user_pass) : user_pass(user_pass),i(0) {}
    operator bool(void) const {
      return (i<user_pass_size && !user_pass[i].empty());
    }
    bool full(void) const {return i>=user_pass_size;}
    bool operator++(void) {
      if (!operator bool()) return false;
      i += 2;
      return operator bool();
    }
    const std::string &getUser(void) const {return user_pass[i  ];}
    const std::string &getPass(void) const {return user_pass[i+1];}
  private:
    const std::string *const user_pass;
    int i;
  };
  UserPassIterator getUserPass(void) const {
    return UserPassIterator(user_pass);
  }
  void clearUserPass(void) {
    for (int i=0;i<user_pass_size;i++) user_pass[i].clear();
  }
  bool setUserPass(const std::string &user,const std::string &pass) {
      // password can be empty, but user cannot.
    if (!user.empty()) {
      for (int i=0;i<user_pass_size;i+=2) {
        if (user_pass[i].empty() || user_pass[i] == user) {
          user_pass[i  ] = user;
          user_pass[i+1] = pass;
          return true;
        }
      }
    }
    return false;
  }
  bool removeUser(const std::string &user) {
    if (!user.empty()) {
      for (int i=0;i<user_pass_size;i+=2) {
        if (user_pass[i] == user) {
          for (;i<user_pass_size-2;i+=2) {
            user_pass[i  ] = user_pass[i+2];
            user_pass[i+1] = user_pass[i+3];
          }
          user_pass[i  ].clear();
          user_pass[i+1].clear();
          return true;
        }
      }
    }
    return false;
  }
  uint16_t rtspPort = 0;
  uint16_t httpPort = 0;
  uint16_t httpsPort = 0;
  uint16_t rtspsPort = 0;
  uint32_t bind_to_interface_rtsp = 0;
  uint32_t bind_to_interface_http = 0;
  uint32_t bind_to_interface_https = 0;
  uint32_t bind_to_interface_rtsps = 0;
  bool use_ipv6_rtsp = false;
  bool use_ipv6_http = false;
  bool use_ipv6_https = false;
  bool use_ipv6_rtsps = false;
  bool rtsp_is_optional = false;
  bool http_is_optional = false;
  bool https_is_optional = false;
  bool rtsps_is_optional = false;
  std::string tls_cert_file;
  std::string tls_key_file;
private:
    // I would prefer std::map, but this would crash in RTSPParameters constructor
    // because std::map is actually a different class in Release vs Debug mode.
    // Using a Release-Plugin with a Debug Binary would crash.
  enum {user_pass_size = 20}; // 10 times {user,pass}
  std::string user_pass[user_pass_size];
};


#ifdef _WIN32
#ifdef RTCMEDIALIB_EXPORTS
#define RTCMEDIALIB_API __declspec(dllexport)
#else
#define RTCMEDIALIB_API __declspec(dllimport)
#endif
#else
#define RTCMEDIALIB_API
#endif

typedef const char *(InitializeMPluginFunc)(
                    const char *interface_api_version_of_caller,
                    IMStreamFactory *streamManager,
                    const MPluginParams &params);

#define RTCMEDIALIB_API_VERSION "0.12"
    // will return the API version of the Library.
    // when the interface_api_version_of_caller does not match,
    // the library will not call the stream_factory.
extern "C" RTCMEDIALIB_API
const char *InitializeMPlugin(
              const char *interface_api_version_of_caller,
              IMStreamFactory *stream_factory,
              const MPluginParams &params);

} // end of namespace InterfaceMediaStream

#endif
