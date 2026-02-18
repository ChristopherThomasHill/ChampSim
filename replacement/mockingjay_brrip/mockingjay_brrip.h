#ifndef REPLACEMENT_MOCKINGJAY_BRRIP_H
#define REPLACEMENT_MOCKINGJAY_BRRIP_H

#include <unordered_map>

#include "cache.h"
#include "modules.h"

class mockingjay_brrip : public champsim::modules::replacement {
  const long NUM_SET;
  const long NUM_WAY;

  const long DATA_WAYS;
  
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
    uint64_t signature;
    int timestamp;
  };
  std::unordered_map<uint64_t, SampledCacheLine* > sampled_cache;

  std::vector<std::vector<int>> rrip;

  bool is_sampled_set(long set);
  uint64_t CRC_HASH(uint64_t _blockAddress);
  uint64_t build_signature(champsim::address ip, uint8_t hit, bool prefetch, uint32_t core);
  uint64_t get_sampled_cache_index(uint64_t full_addr);
  uint64_t get_sampled_cache_tag(uint64_t x);
  int search_sampled_cache(uint64_t blockAddress, uint32_t set);
  void detrain(uint32_t set, int way);
  int temporal_difference(int init, int sample);
  int increment_timestamp(int input);
  int time_elapsed(int global, int local);

public:

  explicit mockingjay_brrip(CACHE* cache);
  mockingjay_brrip(CACHE* cache, long sets, long ways);

  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type);
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit);
};

#endif
