#ifndef PREFETCHER_CMC_NO_CACHE_H
#define PREFETCHER_CMC_NO_CACHE_H

#include <cstdint>
#include <deque>
#include <unordered_map>

#include "champsim.h"
#include "channel.h"
#include "metadata.h"
#include "modules.h"

class cmc_no_cache : public champsim::modules::prefetcher
{
  using prefetcher::prefetcher;

  const unsigned int trigger_buffer_size = 4;
  const int degree = 4;
  unsigned int metadata_sets;
  unsigned int metadata_ways;

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


  struct StorageEntry {
    bool valid = false;
    uint64_t addr;
    uint8_t lru_info;
    std::vector<champsim::block_number> addresses;
  };
  std::vector<std::vector<StorageEntry>> storage;

  uint64_t metadata_addr(champsim::address ip, champsim::block_number block_addr);
  uint32_t metadata_set(uint64_t metadata_addr);
  StorageEntry* find_entry(uint64_t search_addr);
  StorageEntry* access_entry(uint64_t addr);
  StorageEntry* find_victim(uint64_t addr);

public:

  std::map<champsim::address, champsim::block_number> training_unit;

  void prefetcher_initialize();
  uint32_t prefetcher_cache_operate(champsim::address, champsim::address, uint8_t, bool, access_type, uint32_t metadata_in);
};

#endif
