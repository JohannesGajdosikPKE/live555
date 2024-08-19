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
// Copyright (c) 1996-2022 Live Networks, Inc.  All rights reserved.
// Basic Usage Environment: for a simple, non-scripted, console application
// Implementation


#include "BasicUsageEnvironment.hh"
#include "HandlerSet.hh"
#include <GroupsockHelper.hh>
#include <stdio.h>
#if defined(_QNX4)
#include <sys/select.h>
#include <unix.h>
#endif

#if defined(__WIN32__) || defined(_WIN32)
extern "C" int initializeWinsockIfNecessary();
#define ERRNO_BAD_FD WSAENOTSOCK
#else
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
#define ERRNO_BAD_FD EBADF
#endif

const char *PrintSocket(char tmp[],const int tmp_size,const int s) {
  if (tmp_size < 11+2+2*(INET6_ADDRSTRLEN+1+5)+2) {
    tmp[0] = '\0';
  } else {
    sprintf(tmp,"%d(",s);
    size_t l = strlen(tmp);
    struct sockaddr_storage sock_addr;
    socklen_t sock_addrlen = sizeof(sock_addr);
    char port_str[8];
    sock_addrlen = sizeof(sock_addr);
    if (getsockname(s, (struct sockaddr*)&sock_addr, &sock_addrlen) ||
        getnameinfo((struct sockaddr*)&sock_addr, sock_addrlen,
                    tmp+l, INET6_ADDRSTRLEN+1, port_str+1, 6,
                    NI_NUMERICHOST | NI_NUMERICSERV)) {
      strcpy(tmp+l,"unknown");
    } else {
      port_str[0] = ':';
      strcat(tmp,port_str);
      l += strlen(tmp+l);
      if (getpeername(s, (struct sockaddr*)&sock_addr, &sock_addrlen) ||
          getnameinfo((struct sockaddr*)&sock_addr, sock_addrlen,
                      tmp+l+1, INET6_ADDRSTRLEN+1, port_str+1, 6,
                      NI_NUMERICHOST | NI_NUMERICSERV)) {
      } else {
        tmp[l] = '-';
        strcat(tmp,port_str);
      }
    }
    strcat(tmp,")");
  }
  return tmp;
}

////////// BasicTaskScheduler //////////

BasicTaskScheduler* BasicTaskScheduler::createNew(unsigned maxSchedulerGranularity) {
  return new BasicTaskScheduler(maxSchedulerGranularity);
}

BasicTaskScheduler::BasicTaskScheduler(unsigned maxSchedulerGranularity)
  : fMaxSchedulerGranularity(maxSchedulerGranularity), fMaxNumSockets(0)
#if defined(__WIN32__) || defined(_WIN32)
  , fDummySocketNum(-1)
#endif
{
#if defined(__WIN32__) || defined(_WIN32)
  if (!initializeWinsockIfNecessary()) abort();
  int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener == INVALID_SOCKET) abort();
  int reuse = 1;
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                 (char*)&reuse,sizeof(reuse))) abort();
  struct sockaddr_in a;
  memset(&a, 0, sizeof(struct sockaddr_in));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  if (bind(listener, (sockaddr*)&a, sizeof(a))) abort();
    // bind has chosen a free port, get it:
  int namelen = sizeof(a);
  if (getsockname(listener, (sockaddr*)&a, &namelen)) abort();
  if (listen(listener, 1)) abort();
  command_pipe[0] = socket(AF_INET, SOCK_STREAM, 0);
  if (command_pipe[0] == INVALID_SOCKET) abort();
  if (connect(command_pipe[0], (sockaddr*)&a, sizeof(a))) abort();
  command_pipe[1] = accept(listener, 0, 0);
  if (command_pipe[1] == INVALID_SOCKET) abort();
  if (::closeSocket(listener)) abort();
#else
  if (pipe2(command_pipe, O_CLOEXEC)) abort();
#endif
  if (!makeSocketNonBlocking(command_pipe[0])) abort();

  FD_ZERO(&fReadSet);
  FD_ZERO(&fWriteSet);
  FD_ZERO(&fExceptionSet);

  if (maxSchedulerGranularity > 0) schedulerTickTask(); // ensures that we handle events frequently
  setBackgroundHandling(command_pipe[0], SOCKET_READABLE | SOCKET_EXCEPTION, CommandRequestHandler, this);
}

uint64_t BasicTaskScheduler::executeCommand(std::function<void(uint64_t task_nr)> &&cmd) {
  uint64_t rval;
  {
    std::lock_guard<std::mutex> guard(command_queue_mutex);
    rval = command_sequence++;
    if (command_sequence == 0) command_sequence = 1;
    command_queue.push_back(Command(std::move(cmd),rval));
  }
  char data = 0;
  for (;;) {
#if defined(__WIN32__) || defined(_WIN32)
    const int rc = send(command_pipe[1], &data, 1, 0);
#else
    const int rc = write(command_pipe[1], &data, 1);
#endif
    if (rc > 0) break;
    if (rc != 0) {
#if defined(__WIN32__) || defined(_WIN32)
      printf("send failed: %d\n", WSAGetLastError());
#else
      printf("send failed: %d\n", errno);
#endif
      abort();
    }
  }
  return rval;
}

bool BasicTaskScheduler::cancelCommand(const uint64_t token) {
  if (token == 0) return false;
  std::lock_guard<std::mutex> guard(command_queue_mutex);
  for (auto it(command_queue.begin());it!=command_queue.end();++it) {
    if (token == it->seq) {
      command_queue.erase(it);
      return true;
    }
  }
  return false;
}

void BasicTaskScheduler::CommandRequestHandler(void* instance, int /*mask*/) {
  ((BasicTaskScheduler*)instance)->commandRequestHandler();
}

void BasicTaskScheduler::commandRequestHandler(void) {
  for (;;) {
    char data;
#if defined(__WIN32__) || defined(_WIN32)
    const int rc = recv(command_pipe[0], &data, 1, 0);
#else
    const int rc = read(command_pipe[0], &data, 1);
#endif
    if (rc == 0) break;
    if (rc < 0) {
#if defined(__WIN32__) || defined(_WIN32)
      if (WSAGetLastError() == WSAEWOULDBLOCK) break;
      printf("recv failed: %d\n", WSAGetLastError());
#else
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      printf("recv failed: %d\n", errno);
#endif
      abort();
    }
    std::function<void(uint64_t task_nr)> f;
    uint64_t task_nr;
    {
      std::lock_guard<std::mutex> guard(command_queue_mutex);
      if (command_queue.empty()) continue;
      task_nr = command_queue.front().seq;
      f.swap(command_queue.front().f);
      command_queue.pop_front();
    }
      // maybe another thread now wants to cancel the command before it is executed
      // the cancelling will fail.
      // or the same thread might try to cancel the command from its own command callback
    f(task_nr);
  }
}

BasicTaskScheduler::~BasicTaskScheduler() {
#if defined(__WIN32__) || defined(_WIN32)
  if (fDummySocketNum >= 0) closeSocket(fDummySocketNum);
#endif
  ::closeSocket(command_pipe[0]);
  ::closeSocket(command_pipe[1]);
}

void BasicTaskScheduler::schedulerTickTask(void* clientData) {
  ((BasicTaskScheduler*)clientData)->schedulerTickTask();
}

void BasicTaskScheduler::schedulerTickTask() {
  scheduleDelayedTask(fMaxSchedulerGranularity, schedulerTickTask, this);
}

#ifndef MILLION
#define MILLION 1000000
#endif

void BasicTaskScheduler::SingleStep(unsigned maxDelayTime) {
  assertSameThread();
  fd_set readSet = fReadSet; // make a copy for this select() call
  fd_set writeSet = fWriteSet; // ditto
  fd_set exceptionSet = fExceptionSet; // ditto

  DelayInterval const& timeToDelay = fDelayQueue.timeToNextAlarm();
  struct timeval tv_timeToDelay;
  tv_timeToDelay.tv_sec = timeToDelay.seconds();
  tv_timeToDelay.tv_usec = timeToDelay.useconds();
  // Very large "tv_sec" values cause select() to fail.
  // Don't make it any larger than 1 million seconds (11.5 days)
  const long MAX_TV_SEC = MILLION;
  if (tv_timeToDelay.tv_sec > MAX_TV_SEC) {
    tv_timeToDelay.tv_sec = MAX_TV_SEC;
  }
  // Also check our "maxDelayTime" parameter (if it's > 0):
  if (maxDelayTime > 0 &&
      (tv_timeToDelay.tv_sec > (long)maxDelayTime/MILLION ||
       (tv_timeToDelay.tv_sec == (long)maxDelayTime/MILLION &&
	tv_timeToDelay.tv_usec > (long)maxDelayTime%MILLION))) {
    tv_timeToDelay.tv_sec = maxDelayTime/MILLION;
    tv_timeToDelay.tv_usec = maxDelayTime%MILLION;
  }

  int selectResult = select(fMaxNumSockets, &readSet, &writeSet, &exceptionSet, &tv_timeToDelay);
  if (selectResult < 0) {
#if defined(__WIN32__) || defined(_WIN32)
    int err = WSAGetLastError();
    // For some unknown reason, select() in Windoze sometimes fails with WSAEINVAL if
    // it was called with no entries set in "readSet".  If this happens, ignore it:
    if (err == WSAEINVAL && readSet.fd_count == 0) {
      err = EINTR;
      // To stop this from happening again, create a dummy socket:
      char tmp[256];
      if (fDummySocketNum >= 0) {
        envir() << "BasicTaskScheduler::SingleStep() closing dummy socket " << PrintSocket(tmp,sizeof(tmp),fDummySocketNum) << "\n";
        FD_CLR((unsigned)fDummySocketNum, &fReadSet);
        closeSocket(fDummySocketNum);
      }
      fDummySocketNum = socket(AF_INET, SOCK_DGRAM, 0);
      envir() << "BasicTaskScheduler::SingleStep() opening dummy socket " << PrintSocket(tmp,sizeof(tmp),fDummySocketNum) << "\n";
      FD_SET((unsigned)fDummySocketNum, &fReadSet);
    }
    if (err != EINTR) {
#else
    int err = errno;
    if (err != EINTR && err != EAGAIN) {
#endif

    if (err == ERRNO_BAD_FD) {
      envir() << "BasicTaskScheduler::SingleStep(): select() failed: " << err << ", removing bad sockets from sets\n";
      for (int i = 0; i < 10000; ++i) {
        if (FD_ISSET(i, &fReadSet) || FD_ISSET(i, &fWriteSet) || FD_ISSET(i, &fExceptionSet)) {
          int val;
          socklen_t length = sizeof(val);
          if (getsockopt(i, SOL_SOCKET, SO_TYPE, (char*)&val, &length)) {
            envir() << "BasicTaskScheduler::SingleStep(): removing bad socket " << i << " from sets\n";
            FD_CLR(i, &fReadSet);
            FD_CLR(i, &fWriteSet);
            FD_CLR(i, &fExceptionSet);
          }
        }
      }
      fLastHandledSocketNum = -1;//because we didn't call a handler
      goto continue_without_sockets;
    } else {
        
        // Unexpected error - treat this as fatal:
	envir() << "FATAL: BasicTaskScheduler::SingleStep(): select() failed: " << err << "\n";
	envir().setResultErrMsg("FATAL: BasicTaskScheduler::SingleStep(): select() failed: ",err);
	envir() << envir().getResultMsg() << "\n";
#if !defined(_WIN32_WCE)
	perror("BasicTaskScheduler::SingleStep(): select() fails");
	// Because this failure is often "Bad file descriptor" - which is caused by an invalid socket number (i.e., a socket number
	// that had already been closed) being used in "select()" - we print out the sockets that were being used in "select()",
	// to assist in debugging:
	envir() << "socket numbers used in the select() call:\n";
	char tmp[256];
	for (int i = 0; i < 10000; ++i) {
	  if (FD_ISSET(i, &fReadSet) || FD_ISSET(i, &fWriteSet) || FD_ISSET(i, &fExceptionSet)) {
	    envir() << " " << PrintSocket(tmp,sizeof(tmp),i) << "(";
	    if (FD_ISSET(i, &fReadSet)) envir() << "r";
	    if (FD_ISSET(i, &fWriteSet)) envir() << "w";
	    if (FD_ISSET(i, &fExceptionSet)) envir() << "e";
	    envir() << ")";
	  }
	}
	envir() << "\n";
#endif
	internalError();
      }
  }
  }

  {
  // Call the handler function for one readable socket:
  HandlerIterator iter(*fHandlers);
  HandlerDescriptor* handler;
  // To ensure forward progress through the handlers, begin past the last
  // socket number that we handled:
  if (fLastHandledSocketNum >= 0) {
    while ((handler = iter.next()) != NULL) {
      if (handler->socketNum == fLastHandledSocketNum) break;
    }
    if (handler == NULL) {
      fLastHandledSocketNum = -1;
      iter.reset(); // start from the beginning instead
    }
  }
  while ((handler = iter.next()) != NULL) {
    int sock = handler->socketNum; // alias
    int resultConditionSet = 0;
    if (FD_ISSET(sock, &readSet) && FD_ISSET(sock, &fReadSet)/*sanity check*/) resultConditionSet |= SOCKET_READABLE;
    if (FD_ISSET(sock, &writeSet) && FD_ISSET(sock, &fWriteSet)/*sanity check*/) resultConditionSet |= SOCKET_WRITABLE;
    if (FD_ISSET(sock, &exceptionSet) && FD_ISSET(sock, &fExceptionSet)/*sanity check*/) resultConditionSet |= SOCKET_EXCEPTION;
    if ((resultConditionSet&handler->conditionSet) != 0 && handler->handlerProc != NULL) {
      fLastHandledSocketNum = sock;
          // Note: we set "fLastHandledSocketNum" before calling the handler,
          // in case the handler calls "doEventLoop()" reentrantly.
      (*handler->handlerProc)(handler->clientData, resultConditionSet);
      break;
    }
  }
  if (handler == NULL && fLastHandledSocketNum >= 0) {
    // We didn't call a handler, but we didn't get to check all of them,
    // so try again from the beginning:
    iter.reset();
    while ((handler = iter.next()) != NULL) {
      int sock = handler->socketNum; // alias
      int resultConditionSet = 0;
      if (FD_ISSET(sock, &readSet) && FD_ISSET(sock, &fReadSet)/*sanity check*/) resultConditionSet |= SOCKET_READABLE;
      if (FD_ISSET(sock, &writeSet) && FD_ISSET(sock, &fWriteSet)/*sanity check*/) resultConditionSet |= SOCKET_WRITABLE;
      if (FD_ISSET(sock, &exceptionSet) && FD_ISSET(sock, &fExceptionSet)/*sanity check*/) resultConditionSet |= SOCKET_EXCEPTION;
      if ((resultConditionSet&handler->conditionSet) != 0 && handler->handlerProc != NULL) {
	fLastHandledSocketNum = sock;
	    // Note: we set "fLastHandledSocketNum" before calling the handler,
            // in case the handler calls "doEventLoop()" reentrantly.
	(*handler->handlerProc)(handler->clientData, resultConditionSet);
	break;
      }
    }
    if (handler == NULL) fLastHandledSocketNum = -1;//because we didn't call a handler
  }
  }
  continue_without_sockets:
  // Also handle any newly-triggered event (Note that we do this *after* calling a socket handler,
  // in case the triggered event handler modifies The set of readable sockets.)
  if (fTriggersAwaitingHandling != 0) {
    if (fTriggersAwaitingHandling == fLastUsedTriggerMask) {
      // Common-case optimization for a single event trigger:
      fTriggersAwaitingHandling &=~ fLastUsedTriggerMask;
      if (fTriggeredEventHandlers[fLastUsedTriggerNum] != NULL) {
	(*fTriggeredEventHandlers[fLastUsedTriggerNum])(fTriggeredEventClientDatas[fLastUsedTriggerNum]);
      }
    } else {
      // Look for an event trigger that needs handling (making sure that we make forward progress through all possible triggers):
      unsigned i = fLastUsedTriggerNum;
      EventTriggerId mask = fLastUsedTriggerMask;

      do {
	i = (i+1)%MAX_NUM_EVENT_TRIGGERS;
	mask >>= 1;
	if (mask == 0) mask = 0x80000000;

	if ((fTriggersAwaitingHandling&mask) != 0) {
	  fTriggersAwaitingHandling &=~ mask;
	  if (fTriggeredEventHandlers[i] != NULL) {
	    (*fTriggeredEventHandlers[i])(fTriggeredEventClientDatas[i]);
	  }

	  fLastUsedTriggerMask = mask;
	  fLastUsedTriggerNum = i;
	  break;
	}
      } while (i != fLastUsedTriggerNum);
    }
  }

  // Also handle any delayed event that may have come due.
  fDelayQueue.handleAlarm();
}

void BasicTaskScheduler::assertValidSocketForSelect(int socketNum) {
  int val;
  socklen_t length = sizeof(val);
  int rc = getsockopt(socketNum, SOL_SOCKET, SO_TYPE, (char*)&val, &length);
  if (rc) {
#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
    const int err = WSAGetLastError();
#else
    const int err = errno;
    if (err == ENOTSOCK) {
      struct stat stat_buf;
      const int stat_rc = fstat(socketNum,&stat_buf);
      if (stat_rc == 0 && S_ISFIFO(stat_buf.st_mode)) {
        return;
      }
    }
#endif
    if (envirInitialized()) {
      char tmp[256];
      envir() << "FATAL: BasicTaskScheduler::assertValidSocketForSelect(" << PrintSocket(tmp,sizeof(tmp),socketNum) << "): getsockopt(SO_TYPE) failed: " << err << "\n";
      envir().setResultErrMsg("FATAL: BasicTaskScheduler::assertValidSocketForSelect(): getsockopt(SO_TYPE) failed: ",err);
      envir() << envir().getResultMsg() << "\n";
    } else {
#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
      printf("getsockopt failed: %d\n",err);
#else
      printf("getsockopt failed: %d %s\n",err,strerror(err));
#endif
    }
    internalError();
  }
    // The socket may be a datagram socket, a listening socket, or a nonblocking TCP socket with connecting still in progress.
    // This is legal, but there is no peer name.
    // Or a connected TCP socket with a peer name.
    // No further checking.
}

void BasicTaskScheduler
  ::setBackgroundHandling(int socketNum, int conditionSet, BackgroundHandlerProc* handlerProc, void* clientData) {
  assertSameThread();
  if (socketNum < 0) return;
#if !defined(__WIN32__) && !defined(_WIN32) && defined(FD_SETSIZE)
  if (socketNum >= (int)(FD_SETSIZE)) return;
#endif
  if (envirInitialized()) {
    char tmp[256];
    envir() << "BasicTaskScheduler::setBackgroundHandling(" << PrintSocket(tmp,sizeof(tmp),socketNum) << "): FdSets: "
            << ((conditionSet&SOCKET_READABLE) ? "+r" : "-r")
            << ((conditionSet&SOCKET_WRITABLE) ? "+w" : "-w")
            << ((conditionSet&SOCKET_EXCEPTION) ? "+e" : "-e")
            << "\n";
  }
  FD_CLR((unsigned)socketNum, &fReadSet);
  FD_CLR((unsigned)socketNum, &fWriteSet);
  FD_CLR((unsigned)socketNum, &fExceptionSet);
  if (conditionSet == 0) {
    fHandlers->clearHandler(socketNum);
    if (socketNum+1 == fMaxNumSockets) {
      --fMaxNumSockets;
    }
  } else {
    assertValidSocketForSelect(socketNum);
    fHandlers->assignHandler(socketNum, conditionSet, handlerProc, clientData);
    if (socketNum+1 > fMaxNumSockets) {
      fMaxNumSockets = socketNum+1;
    }
    if (conditionSet&SOCKET_READABLE) FD_SET((unsigned)socketNum, &fReadSet);
    if (conditionSet&SOCKET_WRITABLE) FD_SET((unsigned)socketNum, &fWriteSet);
    if (conditionSet&SOCKET_EXCEPTION) FD_SET((unsigned)socketNum, &fExceptionSet);
  }
}

void BasicTaskScheduler::moveSocketHandling(int oldSocketNum, int newSocketNum) {
  assertSameThread();
  if (oldSocketNum < 0 || newSocketNum < 0) return; // sanity check
#if !defined(__WIN32__) && !defined(_WIN32) && defined(FD_SETSIZE)
  if (oldSocketNum >= (int)(FD_SETSIZE) || newSocketNum >= (int)(FD_SETSIZE)) return; // sanity check
#endif
  char tmp[256];
  envir() << "BasicTaskScheduler::moveSocketHandling: "
             "moving from " << PrintSocket(tmp,sizeof(tmp),oldSocketNum);
  envir() << " to " << PrintSocket(tmp,sizeof(tmp),newSocketNum) << "\n";
  if (FD_ISSET(oldSocketNum, &fReadSet)) {FD_CLR((unsigned)oldSocketNum, &fReadSet); FD_SET((unsigned)newSocketNum, &fReadSet);}
  if (FD_ISSET(oldSocketNum, &fWriteSet)) {FD_CLR((unsigned)oldSocketNum, &fWriteSet); FD_SET((unsigned)newSocketNum, &fWriteSet);}
  if (FD_ISSET(oldSocketNum, &fExceptionSet)) {FD_CLR((unsigned)oldSocketNum, &fExceptionSet); FD_SET((unsigned)newSocketNum, &fExceptionSet);}
  fHandlers->moveHandler(oldSocketNum, newSocketNum);

  if (oldSocketNum+1 == fMaxNumSockets) {
    --fMaxNumSockets;
  }
  if (newSocketNum+1 > fMaxNumSockets) {
    fMaxNumSockets = newSocketNum+1;
  }
}
