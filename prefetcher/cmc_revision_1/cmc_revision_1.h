#ifndef PREFETCHER_CMC_REVISION_1_H
#define PREFETCHER_CMC_REVISION_1_H

#include <cstdint>
#include <deque>

#include "champsim.h"
#include "channel.h"
#include "metadata.h"
#include "modules.h"

class cmc_revision_1 : public champsim::modules::prefetcher
{
  using prefetcher::prefetcher;

  CACHE* cache = nullptr;

  const unsigned int trigger_buffer_size = 4;
  const int degree = 4;

  class RecordEntry
  {
  
  public:
    champsim::address pc;
    champsim::block_number block_addr;
    RecordEntry(champsim::address _pc, champsim::block_number _block_addr)
        : pc(_pc), block_addr(_block_addr) {}
  };

  std::deque<RecordEntry> trigger;

  class Recorder
  {
  
  public:
    std::vector<champsim::block_number> entries;
    int index;
    const int degree;
    Recorder(int d) : entries(), index(0), degree(d) {}
    bool entry_empty() { return entries.empty(); }
    champsim::block_number get_base_addr() { return entries[0]; }

    bool train_entry(champsim::block_number block_addr);
    void reset();
    const int nr_entry = 16;
  };

  Recorder* recorder;

  struct CMCRequest : public champsim::MetadataRequest 
  {
    enum class request_type : unsigned {
      LOAD = 0,
      STORE
    };

    request_type type;

    champsim::address pc;
    champsim::block_number block_addr;

    // Load
    bool covered;

    // Store
    std::vector<champsim::block_number> entries;

    CMCRequest(request_type _type, champsim::address _pc, champsim::block_number _block_addr, bool _covered)
        : type(_type), pc(_pc), block_addr(_block_addr), covered(_covered)
    {
    }

    CMCRequest(request_type _type, champsim::address _pc, champsim::block_number _block_addr, std::vector<champsim::block_number> _entries)
        : type(_type), pc(_pc), block_addr(_block_addr), entries(_entries)
    {
    }
  };

  struct CMCBlock : public champsim::MetadataBlk
  {
    std::vector<champsim::block_number> addresses;

    CMCBlock(std::vector<champsim::block_number> _addresses)
        : addresses(_addresses)
    {
    }
  };

  champsim::address metadata_addr(champsim::address ip, champsim::block_number block_addr);

public:

  std::map<champsim::address, champsim::block_number> training_unit;

  void prefetcher_initialize();
  uint32_t prefetcher_cache_operate(champsim::address, champsim::address, uint8_t, bool, access_type, uint32_t metadata_in, bool late_prefetch, bool prefetch_from_this);

  void prefetcher_metadata_request_fill(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk);
  void prefetcher_metadata_request_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk, bool hit);

  void prefetcher_metadata_simulate_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk, std::vector<champsim::address>& prefetch_addresses, bool hit);
};

#endif
