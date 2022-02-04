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
#include <stdio.h>

#ifdef _DEBUG
#include <chrono>

#ifdef _WIN32
#include <processthreadsapi.h>
static inline
unsigned int CurrentThreadId(void) {return GetCurrentThreadId();}
#else
static inline
unsigned int CurrentThreadId(void) {return gettid();}
#endif
#endif

////////// BasicUsageEnvironment //////////

#if defined(__WIN32__) || defined(_WIN32)
extern "C" int initializeWinsockIfNecessary();
#endif

BasicUsageEnvironment::BasicUsageEnvironment(TaskScheduler& taskScheduler)
: BasicUsageEnvironment0(taskScheduler) {
#ifdef _DEBUG
  log_start_of_line = true;
  log_file = 0;
#endif
#if defined(__WIN32__) || defined(_WIN32)
  if (!initializeWinsockIfNecessary()) {
    setResultErrMsg("Failed to initialize 'winsock': ");
    reportBackgroundError();
    internalError();
  }
#endif
}

BasicUsageEnvironment::~BasicUsageEnvironment() {
#ifdef _DEBUG
  if (log_file) fclose(log_file);
#endif
}

BasicUsageEnvironment*
BasicUsageEnvironment::createNew(TaskScheduler& taskScheduler) {
  return new BasicUsageEnvironment(taskScheduler);
}

int BasicUsageEnvironment::getErrno() const {
#if defined(__WIN32__) || defined(_WIN32) || defined(_WIN32_WCE)
  return WSAGetLastError();
#else
  return errno;
#endif
}

FILE *BasicUsageEnvironment::getLogFile(void) {
#ifdef _DEBUG
  if (!log_file) {
    char fname[128];
    sprintf(fname,"Live555_%s_%u.log",
            getLogFileName(),CurrentThreadId());
    log_file = fopen(fname,"a");
  }
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
  return log_file;
#else
  return stderr;
#endif
}

UsageEnvironment& BasicUsageEnvironment::operator<<(char const* str) {
  if (str == NULL) str = "(NULL)"; // sanity check
  FILE *f = getLogFile();
  fprintf(f, "%s", str);
#ifdef _DEBUG
  if (str[strlen(str)-1] == '\n') {
    fflush(f);
    log_start_of_line = true;
  }
#endif
  return *this;
}

UsageEnvironment& BasicUsageEnvironment::operator<<(int i) {
  fprintf(getLogFile(), "%d", i);
  return *this;
}

UsageEnvironment& BasicUsageEnvironment::operator<<(unsigned u) {
  fprintf(getLogFile(), "%u", u);
  return *this;
}

UsageEnvironment& BasicUsageEnvironment::operator<<(double d) {
  fprintf(getLogFile(), "%f", d);
  return *this;
}

UsageEnvironment& BasicUsageEnvironment::operator<<(void* p) {
  fprintf(getLogFile(), "%p", p);
  return *this;
}
