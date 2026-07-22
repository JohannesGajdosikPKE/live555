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
// Copyright (c) 1996-2024 Live Networks, Inc.  All rights reserved.
// State encapsulating a TLS connection
// Implementation

#include "TLSState.hh"

////////// TLSState implementation //////////

TLSState::TLSState()
  : isNeeded(False)
#ifndef NO_OPENSSL
  , fHasBeenSetup(False), fCtx(NULL), fCon(NULL)
#endif
{
}

TLSState::~TLSState() {
#ifndef NO_OPENSSL
  reset();
#endif
}

int TLSState::write(const char* data, unsigned count) {
#ifndef NO_OPENSSL
  return SSL_write(fCon, data, count);
#else
  return -1;
#endif
}

int TLSState::read(u_int8_t* buffer, unsigned bufferSize) {
#ifndef NO_OPENSSL
  int result = SSL_read(fCon, buffer, bufferSize);
  if (result <= 0) {
    if (SSL_get_error(fCon, result) == SSL_ERROR_WANT_READ) {
      // The data can't be delivered yet.  Return 0 (bytes read); we'll try again later
      return 0;
    }
    return -1; // assume that the connection has closed
  }
  return result;
#else
  return 0;
#endif
}

void TLSState::nullify() {
#ifndef NO_OPENSSL
  isNeeded = fHasBeenSetup = False;
  fCtx = NULL;
  fCon = NULL;
#endif
}

#ifndef NO_OPENSSL
void TLSState::initLibrary() {
  static Boolean SSLLibraryHasBeenInitialized = False;
  if (!SSLLibraryHasBeenInitialized) {
    (void)SSL_library_init();
    SSLLibraryHasBeenInitialized = True;
  }
}

void TLSState::reset() {
  if (fHasBeenSetup) SSL_shutdown(fCon);

  if (fCon != NULL) { SSL_free(fCon); fCon = NULL; }
  if (fCtx != NULL) { SSL_CTX_free(fCtx); fCtx = NULL; }
}
#endif

