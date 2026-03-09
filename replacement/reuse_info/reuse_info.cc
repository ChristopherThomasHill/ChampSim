#include "reuse_info.h"

#include <algorithm>
#include <cassert>
#include <iostream>

reuse_info::reuse_info(CACHE* cache) : reuse_info(cache, cache->NUM_SET, cache->NUM_WAY) {}

reuse_info::reuse_info(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways), last_used_cycles(static_cast<std::size_t>(sets * ways), 0), set_age(sets, 0) {}

void reuse_info::track_info(long set, champsim::block_number block_addr, champsim::address ip, access_type type)
{
  if (type == access_type::WRITE || type == access_type::TRANSLATION) // Ignore Writes
    return;

  uint64_t addr = block_addr.to<uint64_t>();
  const bool metadata = (type == access_type::METADATA_LOAD) || (type == access_type::METADATA_STORE);
  TrackerKey key{addr, metadata};

  if (tracker.count(key)) {
    if (type == access_type::METADATA_STORE) {
      reuse_table[std::get<2>(tracker[key])].meta_store_after += 1;
    }
    else {
      uint64_t reuse_distance = set_age[set] - std::get<0>(tracker[key]);
      
      if (reuse_distance >= MAX_REUSE) {
        reuse_table[std::get<2>(tracker[key])].no_reuse += 1;
      } else {
        if (type == access_type::PREFETCH)
          reuse_table[std::get<2>(tracker[key])].prefetch_reuse[reuse_distance] += 1;
        else if (type == access_type::METADATA_LOAD)
          reuse_table[std::get<2>(tracker[key])].metadata_load_reuse[reuse_distance] += 1;
        else
          reuse_table[std::get<2>(tracker[key])].demand_reuse[reuse_distance] += 1;
      }
    }
  }

  Signature sig = {ip, type};
  tracker[key] = std::make_tuple(set_age[set], set, sig);
  set_age[set]++;
}

long reuse_info::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                      champsim::address full_addr, access_type type)
{
  auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);

  // Find the way whose last use cycle is most distant
  auto victim = std::min_element(begin, end);
  assert(begin <= victim);
  assert(victim < end);
  return std::distance(begin, victim);
}

void reuse_info::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                 access_type type)
{
  if (way == NUM_WAY) return;

  // Mark the way as being used on the current cycle
  last_used_cycles.at((std::size_t)(set * NUM_WAY + way)) = cycle++;
}

void reuse_info::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                   champsim::address victim_addr, access_type type, uint8_t hit)
{
  track_info(set, champsim::block_number(full_addr), ip, type);

  // Mark the way as being used on the current cycle
  if (hit && access_type{type} != access_type::WRITE) // Skip this for writeback hits
    last_used_cycles.at((std::size_t)(set * NUM_WAY + way)) = cycle++;
}

void reuse_info::replacement_final_stats()
{
  for (const auto& [key, dataTuple] : tracker) {
    const auto& [age, set, sig] = dataTuple;

    if (set_age[set] - age >= MAX_REUSE) {
      reuse_table[sig].no_reuse += 1;
    }
  }

  const uint64_t BIN_SIZE = 16;
  const uint64_t NUM_BINS = (MAX_REUSE + 1) / BIN_SIZE; // e.g. 512 / 16 = 32 bins

  // 1. Helper structure for sorting
  struct SortableSig {
      const Signature* sig_ptr;
      const ReuseInfo* info_ptr;
      uint64_t total_count;
  };

  std::vector<SortableSig> sorted_list;

  // 2. Iterate, Sum, and Filter
  for (const auto& entry : reuse_table) {
      const Signature& sig = entry.first;
      const ReuseInfo& info = entry.second;

      uint64_t total = 0;
      
      auto sum_map_total = [&](const std::unordered_map<uint64_t, uint64_t>& m) {
          for (auto const& [dist, count] : m) total += count;
      };

      sum_map_total(info.prefetch_reuse);
      sum_map_total(info.demand_reuse);
      sum_map_total(info.metadata_load_reuse);

      total += info.no_reuse;
      total += info.meta_store_after;

      if (total >= 30) {
          sorted_list.push_back({&sig, &info, total});
      }
  }

  // 3. Sort by total_count (Descending)
  std::sort(sorted_list.begin(), sorted_list.end(), 
      [](const SortableSig& a, const SortableSig& b) {
          return a.total_count > b.total_count;
      });

  // ---------------------------------------------------------
  // 4. Print Dynamic Header
  // ---------------------------------------------------------
  std::cout << "PC,AccessType,TotalSigSeen,NoReuse,MetaStoreAfter";

  // We define the types in an array to loop over them for the header
  std::string types[] = {"Prefetch", "Demand", "MetaLoad"};

  for (const std::string& type_name : types) {
      for (uint64_t i = 0; i < NUM_BINS; ++i) {
          uint64_t start = i * BIN_SIZE;
          uint64_t end = start + BIN_SIZE - 1;
          // Output format: Prefetch_0-15, Prefetch_16-31, ...
          std::cout << "," << type_name << "_" << start << "-" << end;
      }
  }
  std::cout << "\n";

  // ---------------------------------------------------------
  // 5. Print Data Rows
  // ---------------------------------------------------------
  for (const auto& item : sorted_list) {
      const Signature& sig = *item.sig_ptr;
      const ReuseInfo& info = *item.info_ptr;

      // Print Signature Metadata
      std::cout << "0x" << std::hex << sig.pc.to<uint64_t>() << std::dec << "," 
                << access_type_names[static_cast<int>(sig.type)] << ","
                << item.total_count << ","
                << reuse_table[sig].no_reuse << ","
                << reuse_table[sig].meta_store_after;

      // Helper to sum a specific map for a specific bin index
      auto get_bin_sum = [&](const std::unordered_map<uint64_t, uint64_t>& m, uint64_t bin_idx) {
          uint64_t sum = 0;
          uint64_t start = bin_idx * BIN_SIZE;
          for (uint64_t k = 0; k < BIN_SIZE; ++k) {
              auto it = m.find(start + k);
              if (it != m.end()) sum += it->second;
          }
          return sum;
      };

      // Loop 1: Prefetch Columns
      for (uint64_t i = 0; i < NUM_BINS; ++i) std::cout << "," << get_bin_sum(info.prefetch_reuse, i);

      // Loop 2: Demand Columns
      for (uint64_t i = 0; i < NUM_BINS; ++i) std::cout << "," << get_bin_sum(info.demand_reuse, i);

      // Loop 3: MetaLoad Columns
      for (uint64_t i = 0; i < NUM_BINS; ++i) std::cout << "," << get_bin_sum(info.metadata_load_reuse, i);

      std::cout << "\n";
  }
}
