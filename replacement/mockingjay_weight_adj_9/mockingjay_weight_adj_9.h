#ifndef REPLACEMENT_MOCKINGJAY_WEIGHT_ADJ_9_H
#define REPLACEMENT_MOCKINGJAY_WEIGHT_ADJ_9_H

#include <deque>
#include <unordered_map>
#include <utility>

#include "cache.h"
#include "modules.h"

class mockingjay_weight_adj_9 : public champsim::modules::replacement {
  CACHE* cache = nullptr;
  
  const long NUM_SET;
  const long NUM_WAY;
  
  const int LOG2_LLC_SET;
  const int LOG2_LLC_SIZE;
  const int LOG2_SAMPLED_SETS;

  const int HISTORY;
  const int GRANULARITY;

  const int METADATA_HISTORY;
  const int METADATA_GRANULARITY;

  const int INF_RD;
  const int INF_ETR;
  const int MAX_RD;

  const int METADATA_HISTORY_RATIO;

  const int SAMPLED_CACHE_WAYS;
  const int LOG2_SAMPLED_CACHE_SETS;
  const int SAMPLED_CACHE_TAG_BITS;
  const int PC_SIGNATURE_BITS;
  const int TIMESTAMP_BITS;

  const double TEMP_DIFFERENCE;
  const double FLEXMIN_PENALTY;

  const int PREFETCH_SAMPLE_HISTORY;
  const int PREFETCH_SAMPLED_CACHE_WAYS;
  const int LOG2_PREFETCH_SAMPLED_CACHE_SETS;
  const int PREFETCH_SAMPLED_CACHE_INF;
  const int PREFETCH_TIMESTAMP_BITS;

  const int METADATA_SHIFT_ACCURACY;

  const uint64_t METADATA_NO_SIG = 0xdeadbeef;
  
  std::vector<std::vector<int>> etr;
  std::vector<std::vector<uint64_t>> metadata_sig;
  std::vector<int> etr_clock;
  std::vector<int> metadata_etr_clock;

  std::unordered_map<uint64_t, int> rdp;

  std::unordered_map<uint64_t, int> accuracy_hits;
  std::unordered_map<uint64_t, int> accuracy_samples;

  std::vector<int> current_timestamp;
  int prefetch_current_timestamp;

  struct SampledCacheLine
  {
    bool valid = false;
    uint64_t tag;
    uint64_t signature;
    int timestamp;
    bool prefetched; /*only used by prefetch sampled cache*/

    std::shared_ptr<champsim::MetadataBlk> metadata_blk = nullptr;
  };

  std::unordered_map<uint64_t, SampledCacheLine*> data_sampled_cache;
  std::unordered_map<uint64_t, SampledCacheLine*> metadata_sampled_cache;
  std::unordered_map<uint64_t, SampledCacheLine*> prefetch_sampled_cache;
  
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

  uint64_t get_prefetch_sampled_cache_index(uint64_t full_addr);
  uint64_t get_prefetch_sampled_cache_tag(uint64_t x);
  int search_prefetch_sampled_cache(uint64_t blockAddress, uint32_t set);
  void prefetch_detrain(uint32_t set, int way);
  int prefetch_time_elapsed(int local);

  double calculate_value(bool metadata, int etr, double accuracy = 0.0);

  class ReuseProfiler
  {
    const uint64_t MAX_REUSE = 640;

    struct TrackerKey
    {
      champsim::block_number block_num;
      bool is_metadata;

      bool operator==(const TrackerKey& other) const
      {
        return (block_num == other.block_num) && (is_metadata == other.is_metadata);
      }
    };

    struct TrackerKeyHash
    {
      std::size_t operator()(const TrackerKey& k) const
      {
        std::size_t h1 = std::hash<uint64_t>{}(k.block_num.to<uint64_t>());
        std::size_t h2 = std::hash<bool>{}(k.is_metadata);
        return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
      }
    };

    struct Signature
    {
      champsim::address ip;
      access_type type;
      bool hit;

      bool operator==(const Signature& other) const
      {
        return (ip == other.ip) && (type == other.type) && (hit == other.hit);
      }
    };

    struct SignatureKeyHash
    {
      std::size_t operator()(const Signature& k) const
      {
        std::size_t h1 = std::hash<uint64_t>{}(k.ip.to<uint64_t>());
        std::size_t h2 = std::hash<int>{}(static_cast<int>(k.type));
        std::size_t h3 = std::hash<bool>{}(k.hit);

        std::size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
      }
    };

    struct ReuseInfo
    {
      std::unordered_map<uint64_t, uint64_t> prefetch_reuse;
      std::unordered_map<uint64_t, uint64_t> demand_reuse;
      std::unordered_map<uint64_t, uint64_t> metadata_load_reuse;

      uint64_t no_reuse = 0;
      uint64_t meta_store_after = 0;
    };

    std::unordered_map<TrackerKey, std::tuple<uint64_t /*insertion set time*/, long /*set*/, Signature>, TrackerKeyHash> tracker;
    std::unordered_map<Signature, ReuseInfo, SignatureKeyHash> reuse_table;
    std::vector<uint64_t> set_age;
  
  public:

    void track_info(long set, champsim::address full_addr, champsim::address ip, access_type type, bool hit);
    void print_profiler(mockingjay_weight_adj_9* parent);

    explicit ReuseProfiler(long num_sets) : set_age(num_sets, 0) {}
  };

  ReuseProfiler reuse_profiler;

  class MockingjayProfiler
  {
    const int INF_ETR;

    struct Signature
    {
      champsim::address ip;
      access_type type = access_type::WRITE;
      bool hit = false;

      bool operator==(const Signature& other) const
      {
        return (ip == other.ip) && (type == other.type) && (hit == other.hit);
      }
    };

    struct SignatureKeyHash
    {
      std::size_t operator()(const Signature& k) const
      {
        std::size_t h1 = std::hash<uint64_t>{}(k.ip.to<uint64_t>());
        std::size_t h2 = std::hash<int>{}(static_cast<int>(k.type));
        std::size_t h3 = std::hash<bool>{}(k.hit);

        std::size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
      }
    };

    std::vector<std::vector<Signature>> last_signature;
    std::vector<std::vector<bool>> last_signature_valid;

    std::unordered_map<Signature, uint64_t, SignatureKeyHash> bypass_table;
    std::unordered_map<Signature, std::vector<uint64_t>, SignatureKeyHash> insertion_etr_table;
    std::unordered_map<Signature, std::vector<uint64_t>, SignatureKeyHash> hit_etr_table;
    std::unordered_map<Signature, std::vector<uint64_t>, SignatureKeyHash> eviction_etr_table;

  public:

    void record_bypass(champsim::address ip, access_type type);
    void record_update(long set, long way, champsim::address ip, champsim::address victim_addr, access_type type, bool hit, int insert_etr, int current_etr);
    void print_profiler(mockingjay_weight_adj_9* parent);

    explicit MockingjayProfiler(long num_sets, long num_ways, int inf_etr)
        : INF_ETR(inf_etr),
          last_signature(num_sets, std::vector<Signature>(num_ways)),
          last_signature_valid(num_sets, std::vector<bool>(num_ways, false))
    {
    }
  };

  MockingjayProfiler mockingjay_profiler;

public:

  explicit mockingjay_weight_adj_9(CACHE* cache);
  mockingjay_weight_adj_9(CACHE* cache, long sets, long ways);

  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type);
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit, const std::shared_ptr<champsim::MetadataRequest>& meta_request, bool local_pref);
  void replacement_final_stats();
};

#endif
