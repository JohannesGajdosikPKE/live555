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
// Copyright (c) 1996-2024 Live Networks, Inc.  All rights reserved.
// Usage Environment
// Implementation

#include "UsageEnvironment.hh"

#ifndef _WIN32
  #if defined(__GLIBC__) && defined (__GLIBC_MINOR__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 17))
    #include <time.h>
  #else
    #include <sys/time.h>
  #endif
#endif

#include <iostream>

////////// library version constants //////////

extern char const* const UsageEnvironmentLibraryVersionStr = USAGEENVIRONMENT_LIBRARY_VERSION_STRING;
extern int const UsageEnvironmentLibraryVersionInt = USAGEENVIRONMENT_LIBRARY_VERSION_INT;


uint64_t TimeAccounter::GetNow(void) {
#ifdef _WIN32
  LARGE_INTEGER v;
  QueryPerformanceCounter(&v);
  return v.QuadPart;
#else
  #if defined(__GLIBC__) && defined (__GLIBC_MINOR__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 17))
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return 1000000000LL * ts.tv_sec + ts.tv_nsec;
  #else
    struct timeval tv;
    gettimeofday(&tv,0);
    return 1000000LL * ts.tv_sec + ts.tv_usec;
  #endif
#endif
}

const char *LastPartOfName(const char *name) {
  const char *rval = name;
  for (const char *p=name;*p;p++) {
    if (*p == '/' || *p == '\\') rval = p+1;
  }
  return rval;
}

unsigned int TimeAccounter::GetNewId(const char *name) {
  const unsigned int rval = nr_of_counters++;
  if (rval >= NR_OF_IDS) abort();
  counter_names[rval] = LastPartOfName(name);
  return rval;
}

const char *TimeAccounter::counter_names[TimeAccounter::NR_OF_IDS];
static inline unsigned int SetZero(const char **array,unsigned int size) {while (size--) *array++=nullptr;return 0;}
std::atomic<unsigned int> TimeAccounter::nr_of_counters(SetZero(TimeAccounter::counter_names,TimeAccounter::NR_OF_IDS));

const unsigned int account_id_misc = TimeAccounter::GetNewId("misc");
const unsigned int account_id_send = TimeAccounter::GetNewId("send");
const unsigned int account_id_recv = TimeAccounter::GetNewId("recv");
const unsigned int account_id_SSLw = TimeAccounter::GetNewId("SSLw");
const unsigned int account_id_SSLr = TimeAccounter::GetNewId("SSLr");


void TimeAccounter::account(const unsigned int id) {
  const uint64_t now = GetNow();
  const uint64_t elapsed = now - last_now;
  last_now = now;
  AtomicCounter &c(counter[id]);
  c.duration += elapsed;
  c.nr_of_calls++;
}

void TimeAccounter::transferValues(UsageEnvironment &env,Counter *values,unsigned int nr) {
  for (unsigned int i=0;i<nr;++i,++values) {
    AtomicCounter &c(counter[i]);
    const uint64_t v = c.duration.exchange(0);
    const uint64_t n = c.nr_of_calls.exchange(0);
    values->duration += v;
    values->nr_of_calls += n;
  }
}


////////// UsageEnvironment //////////

Boolean UsageEnvironment::reclaim() {
  // We delete ourselves only if we have no remainining state:
  if (liveMediaPriv == NULL && groupsockPriv == NULL) {
    delete this;
    return True;
  }
  (*this) << "UsageEnvironment(" << this << ")::reclaim: cannot delete this, because "
          << (liveMediaPriv?"liveMediaPriv":"")
          << ((liveMediaPriv&&groupsockPriv)?",":"")
          << (groupsockPriv?"groupsockPriv":"")
          << " is/are still used\n";
  return False;
}

UsageEnvironment::UsageEnvironment(TaskScheduler& scheduler,std::ostream &log)
  : liveMediaPriv(NULL), groupsockPriv(NULL), fScheduler(scheduler) {
  fScheduler.setUsageEnvironment(*this,log);
}

UsageEnvironment::~UsageEnvironment() {
}

// By default, we handle 'should not occur'-type library errors by calling abort().  Subclasses can redefine this, if desired.
// (If your runtime library doesn't define the "abort()" function, then define your own (e.g., that does nothing).)
void UsageEnvironment::internalError() {
  fprintf(stderr,"UsageEnvironment::internalError: calling abort();\"");
  abort();
}


TaskScheduler::TaskScheduler()
              :my_thread_id(Live555CurrentThreadId()),
               assert_threads(false),env(0),nr_of_users(0) {
//  std::cout << "TaskScheduler::TaskScheduler(" << my_thread_id << ")" << std::endl << std::flush;
}

TaskScheduler::~TaskScheduler() {
}

void TaskScheduler::assertSameThread(void) const {
  if (assert_threads && !isSameThread()) {
    const unsigned int curr_thread_id = Live555CurrentThreadId();
    if (env) *env << "TaskScheduler(" << my_thread_id << ")::assertSameThread: calling from wrong thread: " << curr_thread_id << "\n";
    abort();
  }
}

void *TaskScheduler::rescheduleDelayedTask(TaskToken& task,
					  int64_t microseconds, TaskFunc* proc,
					  void* clientData) {
  void *const rval = unscheduleDelayedTask(task);
  task = scheduleDelayedTask(microseconds, proc, clientData);
  return rval;
}

// By default, we handle 'should not occur'-type library errors by calling abort().  Subclasses can redefine this, if desired.
void TaskScheduler::internalError() {
  fprintf(stderr,"TaskScheduler::internalError: calling abort();\"");
  abort();
}
