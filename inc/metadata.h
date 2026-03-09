#ifndef METADATA_H
#define METADATA_H

#include <cassert>

namespace champsim
{
struct MetadataRequest {
  virtual ~MetadataRequest() = default;

  virtual bool useful() { return true; };
}; // overwritten by metadata requests
struct MetadataBlk {
  virtual ~MetadataBlk() = default;
}; // overwritten by metadata requests
}

#endif