#ifndef IM_STREAM_H_
#define IM_STREAM_H_

#include <string>
#include <memory>
#include <chrono>

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
typedef std::chrono::time_point<std::chrono::system_clock,DurationType> TimeType;

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
  RTSPParameters(LogCallbackPtr log_cb,void *log_cb_context,
                 StatusCallbackPtr status_cb,void *status_cb_context,
                 uint16_t port,uint16_t httpPort,uint16_t httpsPort,uint32_t bind_to_interface,
                 bool use_ipv6,bool ports_are_optional,
                 const std::string &https_cert_file,const std::string &https_key_path,
                 const std::string &user,const std::string &pass)
    : MPluginParams(log_cb,log_cb_context,status_cb,status_cb_context),
      port(port),httpPort(httpPort),httpsPort(httpsPort),bind_to_interface(bind_to_interface),
      use_ipv6(use_ipv6),ports_are_optional(ports_are_optional),
      https_cert_file(https_cert_file),https_key_path(https_key_path),user(user),pass(pass) {}
  const std::string &getHttpCertFile(void) const {return https_cert_file;}
  const std::string &getHttpKeyPath(void) const {return https_key_path;}
  const std::string &getUser(void) const {return user;}
  const std::string &getPass(void) const {return pass;}
  uint16_t port = 0;
  uint16_t httpPort = 0;
  uint16_t httpsPort = 0;
  uint32_t bind_to_interface = 0;
  bool use_ipv6 = false;
  bool ports_are_optional = false;
private:
  const std::string https_cert_file;
  const std::string https_key_path;
  const std::string user;
  const std::string pass;
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

#define RTCMEDIALIB_API_VERSION "0.9"
    // will return the API version of the Library.
    // when the interface_api_version_of_caller does not match,
    // the library will not call the stream_factory.
extern "C" RTCMEDIALIB_API
const char *InitializeMPlugin(
              const char *interface_api_version_of_caller,
              IMStreamFactory *stream_factory,
              const MPluginParams &params);
#endif
