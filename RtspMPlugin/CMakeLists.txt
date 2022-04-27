cmake_minimum_required(VERSION 3.0)

set(OPENSSL_INCLUDE_PATH "/usr/include" CACHE PATH "path where openssl/ssl.h lives")
if (EXISTS "${OPENSSL_INCLUDE_PATH}/openssl/ssl.h")
  message("openssl include files found at ${OPENSSL_INCLUDE_PATH}")
else()
  message(FATAL_ERROR "openssl include files not found at ${OPENSSL_INCLUDE_PATH}."
          " Use cmake -D OPENSSL_INCLUDE_PATH=<path_where_openssl/ssl.h_lives" )
endif()

if (WIN32)
set(OPENSSL_LIBRARY_PATH "/usr/include" CACHE PATH "path where MT/libssl_static.lib lives")
if (EXISTS "${OPENSSL_LIBRARY_PATH}/MT/libssl_static.lib")
  message("openssl library files found at ${OPENSSL_LIBRARY_PATH}")
else()
  message(FATAL_ERROR "openssl library files not found at ${OPENSSL_LIBRARY_PATH}."
          " Use cmake -D OPENSSL_LIBRARY_PATH=<path_where_MT/libssl_static.lib_lives" )
endif()
else()
endif()

set(CMAKE_CXX_STANDARD 14)

project(RtspMStreamPluginProject)

set(CMAKE_DEBUG_POSTFIX "d")

set(PLUGIN RtspMStreamPlugin)
set(TESTPROG RtspMStreamPluginTest)

set(PLUGIN_SOURCES
  ../groupsock/GroupEId.cpp
  ../groupsock/Groupsock.cpp
  ../groupsock/GroupsockHelper.cpp
  ../groupsock/IOHandlers.cpp
  ../groupsock/NetAddress.cpp
  ../groupsock/NetInterface.cpp
  ../groupsock/inet.c
  ../UsageEnvironment/HashTable.cpp
  ../UsageEnvironment/UsageEnvironment.cpp
  ../UsageEnvironment/strDup.cpp
  ../BasicUsageEnvironment/BasicHashTable.cpp
  ../BasicUsageEnvironment/BasicTaskScheduler.cpp
  ../BasicUsageEnvironment/BasicTaskScheduler0.cpp
  ../BasicUsageEnvironment/BasicUsageEnvironment.cpp
  ../BasicUsageEnvironment/BasicUsageEnvironment0.cpp
  ../BasicUsageEnvironment/DelayQueue.cpp
  ../liveMedia/AC3AudioFileServerMediaSubsession.cpp
  ../liveMedia/AC3AudioRTPSink.cpp
  ../liveMedia/AC3AudioRTPSource.cpp
  ../liveMedia/AC3AudioStreamFramer.cpp
  ../liveMedia/ADTSAudioFileServerMediaSubsession.cpp
  ../liveMedia/ADTSAudioFileSource.cpp
  ../liveMedia/ADTSAudioStreamDiscreteFramer.cpp
  ../liveMedia/AMRAudioFileServerMediaSubsession.cpp
  ../liveMedia/AMRAudioFileSink.cpp
  ../liveMedia/AMRAudioFileSource.cpp
  ../liveMedia/AMRAudioRTPSink.cpp
  ../liveMedia/AMRAudioRTPSource.cpp
  ../liveMedia/AMRAudioSource.cpp
  ../liveMedia/AVIFileSink.cpp
  ../liveMedia/AudioInputDevice.cpp
  ../liveMedia/AudioRTPSink.cpp
  ../liveMedia/Base64.cpp
  ../liveMedia/BasicUDPSink.cpp
  ../liveMedia/BasicUDPSource.cpp
  ../liveMedia/BitVector.cpp
  ../liveMedia/ByteStreamFileSource.cpp
  ../liveMedia/ByteStreamMemoryBufferSource.cpp
  ../liveMedia/ByteStreamMultiFileSource.cpp
  ../liveMedia/DVVideoFileServerMediaSubsession.cpp
  ../liveMedia/DVVideoRTPSink.cpp
  ../liveMedia/DVVideoRTPSource.cpp
  ../liveMedia/DVVideoStreamFramer.cpp
  ../liveMedia/DeviceSource.cpp
  ../liveMedia/DigestAuthentication.cpp
  ../liveMedia/EBMLNumber.cpp
  ../liveMedia/FileServerMediaSubsession.cpp
  ../liveMedia/FileSink.cpp
  ../liveMedia/FramedFileSource.cpp
  ../liveMedia/FramedFilter.cpp
  ../liveMedia/FramedSource.cpp
  ../liveMedia/GSMAudioRTPSink.cpp
  ../liveMedia/GenericMediaServer.cpp
  ../liveMedia/H261VideoRTPSource.cpp
  ../liveMedia/H263plusVideoFileServerMediaSubsession.cpp
  ../liveMedia/H263plusVideoRTPSink.cpp
  ../liveMedia/H263plusVideoRTPSource.cpp
  ../liveMedia/H263plusVideoStreamFramer.cpp
  ../liveMedia/H263plusVideoStreamParser.cpp
  ../liveMedia/H264VideoFileServerMediaSubsession.cpp
  ../liveMedia/H264VideoFileSink.cpp
  ../liveMedia/H264VideoRTPSink.cpp
  ../liveMedia/H264VideoRTPSource.cpp
  ../liveMedia/H264VideoStreamDiscreteFramer.cpp
  ../liveMedia/H264VideoStreamFramer.cpp
  ../liveMedia/H264or5VideoFileSink.cpp
  ../liveMedia/H264or5VideoRTPSink.cpp
  ../liveMedia/H264or5VideoStreamDiscreteFramer.cpp
  ../liveMedia/H264or5VideoStreamFramer.cpp
  ../liveMedia/H265VideoFileServerMediaSubsession.cpp
  ../liveMedia/H265VideoFileSink.cpp
  ../liveMedia/H265VideoRTPSink.cpp
  ../liveMedia/H265VideoRTPSource.cpp
  ../liveMedia/H265VideoStreamDiscreteFramer.cpp
  ../liveMedia/H265VideoStreamFramer.cpp
  ../liveMedia/HLSSegmenter.cpp
  ../liveMedia/HMAC_SHA1.cpp
  ../liveMedia/InputFile.cpp
  ../liveMedia/JPEG2000VideoRTPSink.cpp
  ../liveMedia/JPEG2000VideoRTPSource.cpp
  ../liveMedia/JPEGVideoRTPSink.cpp
  ../liveMedia/JPEGVideoRTPSource.cpp
  ../liveMedia/JPEGVideoSource.cpp
  ../liveMedia/Locale.cpp
  ../liveMedia/MIKEY.cpp
  ../liveMedia/MP3ADU.cpp
  ../liveMedia/MP3ADURTPSink.cpp
  ../liveMedia/MP3ADURTPSource.cpp
  ../liveMedia/MP3ADUTranscoder.cpp
  ../liveMedia/MP3ADUdescriptor.cpp
  ../liveMedia/MP3ADUinterleaving.cpp
  ../liveMedia/MP3AudioFileServerMediaSubsession.cpp
  ../liveMedia/MP3AudioMatroskaFileServerMediaSubsession.cpp
  ../liveMedia/MP3FileSource.cpp
  ../liveMedia/MP3Internals.cpp
  ../liveMedia/MP3InternalsHuffman.cpp
  ../liveMedia/MP3InternalsHuffmanTable.cpp
  ../liveMedia/MP3StreamState.cpp
  ../liveMedia/MP3Transcoder.cpp
  ../liveMedia/MPEG1or2AudioRTPSink.cpp
  ../liveMedia/MPEG1or2AudioRTPSource.cpp
  ../liveMedia/MPEG1or2AudioStreamFramer.cpp
  ../liveMedia/MPEG1or2Demux.cpp
  ../liveMedia/MPEG1or2DemuxedElementaryStream.cpp
  ../liveMedia/MPEG1or2DemuxedServerMediaSubsession.cpp
  ../liveMedia/MPEG1or2FileServerDemux.cpp
  ../liveMedia/MPEG1or2VideoFileServerMediaSubsession.cpp
  ../liveMedia/MPEG1or2VideoRTPSink.cpp
  ../liveMedia/MPEG1or2VideoRTPSource.cpp
  ../liveMedia/MPEG1or2VideoStreamDiscreteFramer.cpp
  ../liveMedia/MPEG1or2VideoStreamFramer.cpp
  ../liveMedia/MPEG2IndexFromTransportStream.cpp
  ../liveMedia/MPEG2TransportFileServerMediaSubsession.cpp
  ../liveMedia/MPEG2TransportStreamAccumulator.cpp
  ../liveMedia/MPEG2TransportStreamDemux.cpp
  ../liveMedia/MPEG2TransportStreamDemuxedTrack.cpp
  ../liveMedia/MPEG2TransportStreamFramer.cpp
  ../liveMedia/MPEG2TransportStreamFromESSource.cpp
  ../liveMedia/MPEG2TransportStreamFromPESSource.cpp
  ../liveMedia/MPEG2TransportStreamIndexFile.cpp
  ../liveMedia/MPEG2TransportStreamMultiplexor.cpp
  ../liveMedia/MPEG2TransportStreamParser.cpp
  ../liveMedia/MPEG2TransportStreamParser_PAT.cpp
  ../liveMedia/MPEG2TransportStreamParser_PMT.cpp
  ../liveMedia/MPEG2TransportStreamParser_STREAM.cpp
  ../liveMedia/MPEG2TransportStreamTrickModeFilter.cpp
  ../liveMedia/MPEG2TransportUDPServerMediaSubsession.cpp
  ../liveMedia/MPEG4ESVideoRTPSink.cpp
  ../liveMedia/MPEG4ESVideoRTPSource.cpp
  ../liveMedia/MPEG4GenericRTPSink.cpp
  ../liveMedia/MPEG4GenericRTPSource.cpp
  ../liveMedia/MPEG4LATMAudioRTPSink.cpp
  ../liveMedia/MPEG4LATMAudioRTPSource.cpp
  ../liveMedia/MPEG4VideoFileServerMediaSubsession.cpp
  ../liveMedia/MPEG4VideoStreamDiscreteFramer.cpp
  ../liveMedia/MPEG4VideoStreamFramer.cpp
  ../liveMedia/MPEGVideoStreamFramer.cpp
  ../liveMedia/MPEGVideoStreamParser.cpp
  ../liveMedia/MatroskaDemuxedTrack.cpp
  ../liveMedia/MatroskaFile.cpp
  ../liveMedia/MatroskaFileParser.cpp
  ../liveMedia/MatroskaFileServerDemux.cpp
  ../liveMedia/MatroskaFileServerMediaSubsession.cpp
  ../liveMedia/Media.cpp
  ../liveMedia/MediaSession.cpp
  ../liveMedia/MediaSink.cpp
  ../liveMedia/MediaSource.cpp
  ../liveMedia/MultiFramedRTPSink.cpp
  ../liveMedia/MultiFramedRTPSource.cpp
  ../liveMedia/OggDemuxedTrack.cpp
  ../liveMedia/OggFile.cpp
  ../liveMedia/OggFileParser.cpp
  ../liveMedia/OggFileServerDemux.cpp
  ../liveMedia/OggFileServerMediaSubsession.cpp
  ../liveMedia/OggFileSink.cpp
  ../liveMedia/OnDemandServerMediaSubsession.cpp
  ../liveMedia/OutputFile.cpp
  ../liveMedia/PassiveServerMediaSubsession.cpp
  ../liveMedia/ProxyServerMediaSession.cpp
  ../liveMedia/QCELPAudioRTPSource.cpp
  ../liveMedia/QuickTimeFileSink.cpp
  ../liveMedia/QuickTimeGenericRTPSource.cpp
  ../liveMedia/RTCP.cpp
  ../liveMedia/RTPInterface.cpp
  ../liveMedia/RTPSink.cpp
  ../liveMedia/RTPSource.cpp
  ../liveMedia/RTSPClient.cpp
  ../liveMedia/RTSPCommon.cpp
  ../liveMedia/RTSPRegisterSender.cpp
  ../liveMedia/RTSPServer.cpp
  ../liveMedia/RTSPServerRegister.cpp
  ../liveMedia/RawVideoRTPSink.cpp
  ../liveMedia/RawVideoRTPSource.cpp
  ../liveMedia/SIPClient.cpp
  ../liveMedia/SRTPCryptographicContext.cpp
  ../liveMedia/ServerMediaSession.cpp
  ../liveMedia/SimpleRTPSink.cpp
  ../liveMedia/SimpleRTPSource.cpp
  ../liveMedia/StreamParser.cpp
  ../liveMedia/StreamReplicator.cpp
  ../liveMedia/T140TextRTPSink.cpp
  ../liveMedia/TLSState.cpp
  ../liveMedia/TextRTPSink.cpp
  ../liveMedia/TheoraVideoRTPSink.cpp
  ../liveMedia/TheoraVideoRTPSource.cpp
  ../liveMedia/VP8VideoRTPSink.cpp
  ../liveMedia/VP8VideoRTPSource.cpp
  ../liveMedia/VP9VideoRTPSink.cpp
  ../liveMedia/VP9VideoRTPSource.cpp
  ../liveMedia/VideoRTPSink.cpp
  ../liveMedia/VorbisAudioRTPSink.cpp
  ../liveMedia/VorbisAudioRTPSource.cpp
  ../liveMedia/WAVAudioFileServerMediaSubsession.cpp
  ../liveMedia/WAVAudioFileSource.cpp
  ../liveMedia/ourMD5.cpp
  ../liveMedia/rtcp_from_spec.c
  ../liveMedia/uLawAudioFilter.cpp
  MStreamPluginRTSPServer.cpp
  SSLSocketBase.cpp
  SSLSocketServerPipe.cpp
  SocketCommunication.cpp
)

add_library(${PLUGIN} SHARED ${PLUGIN_SOURCES})

target_include_directories(${PLUGIN} PUBLIC .)
target_include_directories(${PLUGIN} PRIVATE ../groupsock/include)
target_include_directories(${PLUGIN} PRIVATE ../UsageEnvironment/include)
target_include_directories(${PLUGIN} PRIVATE ../BasicUsageEnvironment/include)
target_include_directories(${PLUGIN} PRIVATE ../liveMedia/include)
target_include_directories(${PLUGIN} PRIVATE ${OPENSSL_INCLUDE_PATH})


add_executable(${TESTPROG} RtspMStreamPluginTestMain.cpp)
target_link_libraries(${TESTPROG} ${PLUGIN})

if (WIN32)
  target_compile_options(${PLUGIN} PRIVATE -DLIVE555_FORCE_BOOLEAN_TYPE=char)
  target_compile_options(${PLUGIN} PRIVATE -D__STDC_LIMIT_MACROS)
  target_compile_options(${PLUGIN} PRIVATE -DNOMINMAX)
  target_compile_options(${PLUGIN} PRIVATE -DNO_GETIFADDRS)
  target_compile_options(${PLUGIN} PRIVATE -DRTCMEDIALIB_EXPORTS)
  target_compile_options(${PLUGIN} PUBLIC -DFD_SETSIZE=1024)
  target_compile_options(${PLUGIN} PUBLIC -MT$<$<CONFIG:Debug>:d>)
  target_link_libraries(${PLUGIN} ws2_32)
  target_link_libraries(${PLUGIN} ${OPENSSL_LIBRARY_PATH}/MT$<$<CONFIG:Debug>:d>/libssl_static$<$<CONFIG:Debug>:d>.lib)
  target_link_libraries(${PLUGIN} ${OPENSSL_LIBRARY_PATH}/MT$<$<CONFIG:Debug>:d>/libcrypto_static$<$<CONFIG:Debug>:d>.lib)
  target_compile_options(${TESTPROG} PUBLIC -MT$<$<CONFIG:Debug>:d>)
else ()
  target_compile_options(${PLUGIN} PUBLIC -DSOCKLEN_T=socklen_t)
  target_compile_options(${PLUGIN} PUBLIC -g)
  target_link_libraries(${PLUGIN} pthread)
  target_link_libraries(${PLUGIN} ssl)
  target_link_libraries(${PLUGIN} dl)
endif ()

