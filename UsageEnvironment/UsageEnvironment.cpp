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

#include <iostream>

////////// library version constants //////////

extern char const* const UsageEnvironmentLibraryVersionStr = USAGEENVIRONMENT_LIBRARY_VERSION_STRING;
extern int const UsageEnvironmentLibraryVersionInt = USAGEENVIRONMENT_LIBRARY_VERSION_INT;

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

UsageEnvironment::UsageEnvironment(TaskScheduler& scheduler)
  : liveMediaPriv(NULL), groupsockPriv(NULL), fScheduler(scheduler) {
  fScheduler.setUsageEnvironment(*this);
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
    std::cout << "TaskScheduler(" << my_thread_id << ")::assertSameThread: calling from wrong thread: " << curr_thread_id << std::endl << std::flush;
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
