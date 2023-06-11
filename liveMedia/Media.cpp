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
// "liveMedia"
// Copyright (c) 1996-2022 Live Networks, Inc.  All rights reserved.
// Media
// Implementation

#include "Media.hh"

#ifndef USE_LIVE555_MEDIATABLE

#include <set>

#include <mutex>

#include <string.h>

class MediaLookupTable {
public:
  static void Add(Medium *m) {
    get().add(m);
  }
  static Medium *Lookup(const char *n) {
    return get().lookup(n);
  }
  static void Remove(const char *n) {
    get().remove(n);
  }
private:
  MediaLookupTable(void) : fNameGenerator(0) {}
  static MediaLookupTable &get(void) {
    static MediaLookupTable t;
    return t;
  }
  struct MediaPointer {
    MediaPointer(void) : m(nullptr) {}
    MediaPointer(Medium *m) : m(m) {}
    Medium *m;
    struct IsLess {
      typedef void is_transparent; // weird C++14 hack for searching non-keys
      bool operator()(MediaPointer a,MediaPointer b) const {return (strcmp(a.m->name(),b.m->name()) < 0);}
      bool operator()(MediaPointer a,const char *b) const {return (strcmp(a.m->name(),b) < 0);}
      bool operator()(const char *a,MediaPointer b) const {return (strcmp(a,b.m->name()) < 0);}
    };
  };
  void add(Medium *m) {
    std::lock_guard<std::mutex> lock(mutex);
    for (;;) {
      ++fNameGenerator;
      if (!fNameGenerator) continue;
      snprintf(m->fMediumName, mediumNameMaxLen, "liveMedia%lu", fNameGenerator++);
      if (table.insert(MediaPointer(m)).second) break;
    }
  }
  Medium *lookup(const char *n) const {
    std::lock_guard<std::mutex> lock(mutex);
    auto it(table.find(n));
    if (it == table.end()) return nullptr;
    return it->m;
  }
  void remove(const char *n) {
    Medium *m = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex);
      auto it(table.find(n));
      if (it == table.end()) return;
      m = it->m;
      table.erase(it);
    }
    delete m;
  }
  unsigned long int fNameGenerator;
  std::set<MediaPointer,MediaPointer::IsLess> table;
  mutable std::mutex mutex;
};

Medium::Medium(UsageEnvironment& env)
	: fEnviron(env), fNextTask(NULL) {
  MediaLookupTable::Add(this);
  env.setResultMsg(fMediumName);
}

Medium::~Medium() {
  // Remove any tasks that might be pending for us:
  fEnviron.taskScheduler().unscheduleDelayedTask(fNextTask);
}

Boolean Medium::lookupByName(UsageEnvironment& env, char const* mediumName,
				  Medium*& resultMedium) {
  resultMedium = MediaLookupTable::Lookup(mediumName);
  if (resultMedium == NULL) {
    env.setResultMsg("Medium ", mediumName, " does not exist");
    return False;
  }

  return True;
}

void Medium::close(UsageEnvironment& env, char const* name) {
  MediaLookupTable::Remove(name);
}

#else

#include "HashTable.hh"

////////// Medium //////////

Medium::Medium(UsageEnvironment& env)
	: fEnviron(env), fNextTask(NULL) {
  // First generate a name for the new medium:
  MediaLookupTable::ourMedia(env)->generateNewName(fMediumName, mediumNameMaxLen);
  env.setResultMsg(fMediumName);

  // Then add it to our table:
  MediaLookupTable::ourMedia(env)->addNew(this, fMediumName);
}

Medium::~Medium() {
  // Remove any tasks that might be pending for us:
  fEnviron.taskScheduler().unscheduleDelayedTask(fNextTask);
}

Boolean Medium::lookupByName(UsageEnvironment& env, char const* mediumName,
				  Medium*& resultMedium) {
  resultMedium = MediaLookupTable::ourMedia(env)->lookup(mediumName);
  if (resultMedium == NULL) {
    env.setResultMsg("Medium ", mediumName, " does not exist");
    return False;
  }

  return True;
}

void Medium::close(UsageEnvironment& env, char const* name) {
  MediaLookupTable::ourMedia(env)->remove(name);
}

#endif

void Medium::close(Medium* medium) {
  if (medium == NULL) return;

  close(medium->envir(), medium->name());
}

Boolean Medium::isSource() const {
  return False; // default implementation
}

Boolean Medium::isSink() const {
  return False; // default implementation
}

Boolean Medium::isRTCPInstance() const {
  return False; // default implementation
}

Boolean Medium::isRTSPClient() const {
  return False; // default implementation
}

Boolean Medium::isRTSPServer() const {
  return False; // default implementation
}

Boolean Medium::isMediaSession() const {
  return False; // default implementation
}

Boolean Medium::isServerMediaSession() const {
  return False; // default implementation
}


////////// _Tables implementation //////////

_Tables* _Tables::getOurTables(UsageEnvironment& env, Boolean createIfNotPresent) {
  if (env.liveMediaPriv == NULL && createIfNotPresent) {
    env.liveMediaPriv = new _Tables(env);
  }
  return (_Tables*)(env.liveMediaPriv);
}

#ifndef USE_LIVE555_MEDIATABLE

void _Tables::reclaimIfPossible() {
  if (socketTable == NULL) {
    fEnv.liveMediaPriv = NULL;
    delete this;
  }
}

_Tables::_Tables(UsageEnvironment& env)
  : socketTable(NULL), fEnv(env) {
}

_Tables::~_Tables() {
}


#else

void _Tables::reclaimIfPossible() {
  if (mediaTable == NULL && socketTable == NULL) {
    fEnv.liveMediaPriv = NULL;
    delete this;
  }
}

_Tables::_Tables(UsageEnvironment& env)
  : mediaTable(NULL), socketTable(NULL), fEnv(env) {
}

_Tables::~_Tables() {
}


////////// MediaLookupTable implementation //////////

MediaLookupTable* MediaLookupTable::ourMedia(UsageEnvironment& env) {
  _Tables* ourTables = _Tables::getOurTables(env);
  if (ourTables->mediaTable == NULL) {
    // Create a new table to record the media that are to be created in
    // this environment:
    ourTables->mediaTable = new MediaLookupTable(env);
  }
  return ourTables->mediaTable;
}

Medium* MediaLookupTable::lookup(char const* name) const {
  return (Medium*)(fTable->Lookup(name));
}

void MediaLookupTable::addNew(Medium* medium, char* mediumName) {
  fTable->Add(mediumName, (void*)medium);
}

void MediaLookupTable::remove(char const* name) {
  Medium* medium = lookup(name);
  if (medium != NULL) {
    fTable->Remove(name);
    if (fTable->IsEmpty()) {
      // We can also delete ourselves (to reclaim space):
      _Tables* ourTables = _Tables::getOurTables(fEnv);
      delete this;
      ourTables->mediaTable = NULL;
      ourTables->reclaimIfPossible();
    }

    delete medium;
  }
}

void MediaLookupTable::generateNewName(char* mediumName,
				       unsigned /*maxLen*/) {
  // We should really use snprintf() here, but not all systems have it
  sprintf(mediumName, "liveMedia%d", fNameGenerator++);
}

MediaLookupTable::MediaLookupTable(UsageEnvironment& env)
  : fEnv(env), fTable(HashTable::create(STRING_HASH_KEYS)), fNameGenerator(0) {
}

MediaLookupTable::~MediaLookupTable() {
  delete fTable;
}

#endif
