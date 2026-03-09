#ifndef REPLACEMENT_MOCKINGJAY_HALF_METADATA_H
#define REPLACEMENT_MOCKINGJAY_HALF_METADATA_H

#include <unordered_map>

#include "cache.h"
#include "modules.h"

class mockingjay_half_metadata : public champsim::modules::replacement {
  const long NUM_SET;
  const long NUM_WAY;
  
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
  std::vector<int> metadata_etr_clock;

  std::unordered_map<uint64_t, int> rdp;

  std::vector<int> current_timestamp;
  std::vector<int> metadata_current_timestamp;

  struct SampledCacheLine
  {
    bool valid;
    uint64_t tag;
    uint64_t signature;
    int timestamp;

    champsim::address ip;
    access_type type;
  };
  std::unordered_map<uint64_t, SampledCacheLine* > sampled_cache;
  std::unordered_map<uint64_t, SampledCacheLine* > metadata_sampled_cache;

  bool is_sampled_set(long set);
  uint64_t CRC_HASH(uint64_t _blockAddress);
  uint64_t build_signature(uint32_t triggering_cpu, champsim::address ip, access_type type, uint8_t hit);
  uint64_t get_sampled_cache_index(uint64_t full_addr);
  uint64_t get_sampled_cache_tag(uint64_t x);
  int search_sampled_cache(uint64_t blockAddress, bool metadata, uint32_t set);
  void detrain(uint32_t set, int way, bool metadata);
  int temporal_difference(int init, int sample);
  int increment_timestamp(int input);
  int time_elapsed(int global, int local);

  struct Signature {
    champsim::address pc;
    access_type type;

    bool operator==(const Signature& other) const {
        return (pc == other.pc) && (type == other.type);
    }
  };

  struct SignatureKeyHash {
    std::size_t operator()(const Signature& k) const {
      std::size_t h1 = std::hash<uint64_t>{}(k.pc.to<uint64_t>());
      std::size_t h2 = std::hash<int>{}(static_cast<int>(k.type));
      return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    }
  };

  struct ReuseInfo {
    std::unordered_map<uint64_t, uint64_t> prefetch_reuse;
    std::unordered_map<uint64_t, uint64_t> demand_reuse;
    std::unordered_map<uint64_t, uint64_t> metadata_load_reuse;

    uint64_t no_reuse = 0;
    uint64_t meta_store_after = 0;
  };

  uint64_t MAX_REUSE = 512;
  std::unordered_map<Signature, ReuseInfo, SignatureKeyHash> reuse_table;
  std::unordered_map<Signature, std::unordered_map<uint64_t, uint64_t>, SignatureKeyHash> sampled_table;
  std::unordered_map<Signature, std::unordered_map<uint64_t, uint64_t>, SignatureKeyHash> prediction_table;
  std::vector<uint64_t> set_age;

  struct TrackerKey {
    uint64_t addr;
    bool metadata;

    bool operator==(const TrackerKey& other) const
    {
      return (addr == other.addr) && (metadata == other.metadata);
    }
  };

  struct TrackerKeyHash {
    std::size_t operator()(const TrackerKey& k) const
    {
      std::size_t h1 = std::hash<uint64_t>{}(k.addr);
      std::size_t h2 = std::hash<bool>{}(k.metadata);
      return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    }
  };

  std::unordered_map<TrackerKey, std::tuple<uint64_t, long, Signature>, TrackerKeyHash> tracker;

  void track_info(long set, champsim::block_number block_addr, champsim::address ip, access_type type);

public:

  explicit mockingjay_half_metadata(CACHE* cache);
  mockingjay_half_metadata(CACHE* cache, long sets, long ways);

  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type);
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, bool hit, bool useful);
  void replacement_final_stats();
};

#endif
