#ifndef REPLACEMENT_REUSE_INFO_H
#define REPLACEMENT_REUSE_INFO_H

#include <vector>
#include <unordered_map>
#include <tuple>

#include "cache.h"
#include "modules.h"

class reuse_info : public champsim::modules::replacement
{
  long NUM_WAY;
  std::vector<uint64_t> last_used_cycles;
  uint64_t cycle = 0;

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
  explicit reuse_info(CACHE* cache);
  reuse_info(CACHE* cache, long sets, long ways);

  // void initialize_replacement();
  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                   champsim::address full_addr, access_type type);
  void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                              access_type type);
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                access_type type, uint8_t hit);
  void replacement_final_stats();
};

#endif
