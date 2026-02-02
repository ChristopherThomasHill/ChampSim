#ifndef METADATA_H
#define METADATA_H

#include <cassert>

namespace champsim
{
struct MetadataRequest {
  virtual bool is_write() {assert(0 && "Undefined MetadataRequest"); return false;}
  virtual bool is_read() {assert(0 && "Undefined MetadataRequest"); return false;}
}; // overwritten by metadata requests
struct MetadataBlk {
}; // overwritten by metadata requests
}

#endif