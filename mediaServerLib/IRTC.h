#ifndef IRTC_H_
#define IRTC_H_

#include <string>
#include <memory>

enum RTCFormat
{
  RTCFormatJPEG = 0,
  RTCFormatH264,
  RTCFormatYUVI420,
  RTCFormatUnknown
};

class SubsessionInfo {
public:
  virtual ~SubsessionInfo(void) {}
  virtual const char *getAuxSdpLine(void) const {return nullptr;}
  virtual RTCFormat GetFormat(void) const {return RTCFormatUnknown;}
  virtual uint32_t GetWidth(void) const {return 0;}
  virtual uint32_t GetHeight(void) const {return 0;}
  virtual uint32_t getEstBitrate(void) const {return 0;}
  virtual uint32_t getRtpTimestampFrequency(void) const {return 0;}
  virtual const char *getSdpMediaTypeString(void) const {return nullptr;}
  virtual const char *getRtpPayloadFormatName(void) const {return nullptr;}
protected:
  SubsessionInfo(void) {}
private:
  SubsessionInfo(const SubsessionInfo&);
  SubsessionInfo &operator=(const SubsessionInfo&);
};

typedef void (*TOnFrameCallbackPtr)(void *callerId, const SubsessionInfo *info,
                                    const uint8_t *buffer, int bufferSize, int64_t frameTime);

class IRTCStream {
public:
  virtual ~IRTCStream(void) {}

    // the SubsessionInfos live on the heap of the executable at the same address
    // at least as long as the IRTCStream lives, last pointer in the array is 0.
    // This information is used for generating the RTSP response
    // and shall stay constant until the stream is closed
  virtual const SubsessionInfo *const *getSubsessionInfoList(void) const = 0;

    // register for frames with the callerId. Can be called many times, the new callback will replace the old one.
    // After the callback is changed, the old callback receives no more frames.
    // The new value can be NULL.
    // After onFrameCallback(callerId,NULL) is called, no more frames will be received
    // until RegisterOnFrame is called again.
  virtual void RegisterOnFrame(void *callerId, TOnFrameCallbackPtr onFrameCallback) = 0;

///  virtual const char* GetLabel() = 0; // what is this? The url from GetStream()?

};

typedef std::shared_ptr<IRTCStream> TStreamPtr;

class IRTCStreamFactory
{
public:
  virtual ~IRTCStreamFactory(void) {}
    // The pluging shall call this function frequently,
    // giving some human readable text about whats going on.
  virtual void OnStatsInfo(const std::string &statsInfo) = 0;
    // called for every log line
  virtual void OnLog(const std::string &message) = 0;

  typedef void (GetStreamCb)(void *context,const TStreamPtr &stream);
  virtual void GetStream(const char *url,void *context,GetStreamCb *cb) = 0;
};


class RTSPParameters {
public:
  RTSPParameters(void) {}
  RTSPParameters(uint16_t port,uint16_t httpPort,uint16_t httpsPort,uint32_t bind_to_interface,
                 const std::string &https_cert_file,const std::string &https_key_path,
                 const std::string &user,const std::string &pass)
    : port(port),httpPort(httpPort),httpsPort(httpsPort),bind_to_interface(bind_to_interface),
      https_cert_file(https_cert_file),https_key_path(https_key_path),user(user),pass(pass) {}
  const std::string &getHttpCertFile(void) const {return https_cert_file;}
  const std::string &getHttpKeyPath(void) const {return https_key_path;}
  const std::string &getUser(void) const {return user;}
  const std::string &getPass(void) const {return pass;}
  uint16_t port = 0;
  uint16_t httpPort = 0;
  uint16_t httpsPort = 0;
  uint32_t bind_to_interface = 0;
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

#define RTCMEDIALIB_API_VERSION "0.3"
    // will return the API version of the Library.
    // when the interface_api_version_of_caller does not match,
    // the library will not call the streamManager.
extern "C" RTCMEDIALIB_API
const char *initializeRTCMediaLib(
              const char *interface_api_version_of_caller,
              IRTCStreamFactory *streamManager,
              const RTSPParameters &params);

#endif
