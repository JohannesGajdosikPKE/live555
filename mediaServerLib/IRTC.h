#ifndef IRTC_H_
#define IRTC_H_

#include <string>
#include <memory>

typedef void (*TOnCloseCallbackPtr)(void *context);

typedef void (*TOnFrameCallbackPtr)(void *callerId, const uint8_t *buffer, int bufferSize, const int64_t &frameTime);

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

class IRTCStream {
public:
  virtual ~IRTCStream(void) {}

    // the SubsessionInfos live on the heap of the executable at the same address
    // at least as long as the IRTCStream lives, last pointer in the array is 0.
    // This information is used for generating the RTSP response
    // and shall stay constant until the stream is closed
  virtual const SubsessionInfo *const *getSubsessionInfoList(void) const = 0;

    // after the onCloseCallback no more frames for any Subsession of this stream will be received
    // until RegisterOnFrame is called again.
    // onCloseCallback is more than receiving onFrameCallback for all registered subsessions,
    // afterwards you must call getSubsessionInfoList again if you want to continue using the stream.
  virtual void RegisterOnClose(void *context, TOnCloseCallbackPtr onCloseCallback) = 0;
    // guarantee: after DeregisterOnClose onCloseCallback will not be called
  void DeregisterOnClose(void *context) {
    RegisterOnClose(context,nullptr);
  }

    // register for frames of the given subsession and associate the Subsession with the callerId.
    // After onFrameCallback(size==0) is called, nno more frames for this Subsession will be received
    // until RegisterOnFrame is called again
  virtual void RegisterOnFrame(void *callerId, const SubsessionInfo *info, TOnFrameCallbackPtr onFrameCallback) = 0;

    // deregister for frames of the associated Subsession,
    // guarantee: after DeregisterOnFrame has returned no more callbacks for the associated Subsession will be called
  void DeregisterOnFrame(void *callerId, const SubsessionInfo *info) {
    RegisterOnFrame(callerId,info,nullptr);
  }

///  virtual const char* GetLabel() = 0; // what is this? The url from GetStream()?

  // The internal thread may call virtual functions, and
  // virtual functions cannot be called from constructors/destructors.
  // Therefore AfterConstruction/BeforeDestruction must be called explicitely
  // to allow the use of an internal thread.
  virtual void AfterConstruction(void) {}
  virtual void BeforeDestruction(void) {}
  virtual bool IsInitialized(void) const { return true; }
};

typedef std::shared_ptr<IRTCStream> TStreamPtr;

class IRTCStreamFactory
{
public:
  virtual ~IRTCStreamFactory(void) {}
  // Callback information about the videoStreamInternalUsage
  virtual void            OnP2PStatsInfo(const char* statsInfo) {}

  typedef void (GetStreamCb)(void *context,const TStreamPtr &stream);
  virtual void GetStream(const char *url,void *context,GetStreamCb *cb) = 0;
};



typedef void(*TLogCallbackPtr)(const std::string& message);

enum RTCLoggingSeverity {
  LS_SENSITIVE,
  LS_VERBOSE,
  LS_INFO,
  LS_WARNING,
  LS_ERROR,
  LS_NONE,
};

struct RTSPParameters
{
  uint16_t port;
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

#define RTCMEDIALIB_API_VERSION "0.1"
    // will return the API version of the Library.
    // when the interface_api_version_of_caller does not match,
    // the library will not call the streamManager.
extern "C" RTCMEDIALIB_API
const char *initializeRTCMediaLib(
              const char *interface_api_version_of_caller,
              IRTCStreamFactory *streamManager,
              const RTSPParameters &params);

#endif
