#include "cmc_lru.h"

#include <algorithm>
#include <cassert>

cmc_lru::cmc_lru(CACHE* cache) : cmc_lru(cache, cache->NUM_SET, cache->NUM_WAY) {}

cmc_lru::cmc_lru(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways), NUM_METADATA_WAY(8), last_used_cycles(static_cast<std::size_t>(sets * ways), 0) {}

long cmc_lru::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                      champsim::address full_addr, access_type type)
{
  assert(type != access_type::METADATA_LOAD);

  auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY + NUM_METADATA_WAY);
  auto end = std::next(begin, NUM_WAY - NUM_METADATA_WAY);

  if (type == access_type::METADATA_LOAD) {
    begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
    end = std::next(begin, NUM_METADATA_WAY);
  }

  // Find the way whose last use cycle is most distant
  auto victim = std::min_element(begin, end);
  assert(begin <= victim);
  assert(victim < end);
  return std::distance(begin, victim);
}

void cmc_lru::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                 access_type type)
{
  // Mark the way as being used on the current cycle
  last_used_cycles.at((std::size_t)(set * NUM_WAY + way)) = cycle++;
}

void cmc_lru::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                   champsim::address victim_addr, access_type type, uint8_t hit)
{
  // Mark the way as being used on the current cycle
  if (hit && access_type{type} != access_type::WRITE) // Skip this for writeback hits
    last_used_cycles.at((std::size_t)(set * NUM_WAY + way)) = cycle++;
}
