#ifndef REPLACEMENT_MOCKINGJAY_SPLIT_10_H
#define REPLACEMENT_MOCKINGJAY_SPLIT_10_H

#include <unordered_map>

#include "cache.h"
#include "modules.h"

class mockingjay_split_10 : public champsim::modules::replacement {
  const long NUM_SET;
  const long NUM_WAY;

  const uint32_t METADATA_WAYS; 
  
  const int LOG2_LLC_SET;
  const int LOG2_LLC_SIZE;
  const int LOG2_SAMPLED_SETS;

  const int HISTORY;
  const int GRANULARITY;

  const int INF_RD;
  const int INF_ETR;
  const int MAX_RD;

  const int SAMPLED_CACHE_WAYS;
  const int LOG2_SAMPLED_CACHE_SETS;
  const int SAMPLED_CACHE_TAG_BITS;
  const int PC_SIGNATURE_BITS;
  const int TIMESTAMP_BITS;

  const double TEMP_DIFFERENCE;
  const double FLEXMIN_PENALTY;
  
  std::vector<std::vector<int>> etr;
  std::vector<int> etr_clock;

  std::unordered_map<uint64_t, int> rdp;

  std::vector<int> current_timestamp;

  struct SampledCacheLine
  {
    bool valid;
    uint64_t tag;
    bool metadata;
    uint64_t signature;
    int timestamp;
  };
  std::unordered_map<uint64_t, SampledCacheLine* > sampled_cache;

  bool is_sampled_set(long set);
  uint64_t CRC_HASH(uint64_t _blockAddress);
  uint64_t build_signature(uint32_t triggering_cpu, champsim::address ip, access_type type, uint8_t hit);
  uint64_t get_sampled_cache_index(uint64_t full_addr);
  uint64_t get_sampled_cache_tag(uint64_t x);
  int search_sampled_cache(uint64_t blockAddress, bool metadata, uint32_t set);
  void detrain(uint32_t set, int way);
  int temporal_difference(int init, int sample);
  int increment_timestamp(int input);
  int time_elapsed(int global, int local);

public:

  explicit mockingjay_split_10(CACHE* cache);
  mockingjay_split_10(CACHE* cache, long sets, long ways);

  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type);
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit);
};

#endif
