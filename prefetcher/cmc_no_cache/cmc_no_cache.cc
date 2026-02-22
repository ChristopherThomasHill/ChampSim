#include "cache.h"

#include "cmc_no_cache.h"

#include <iostream>

#define MAX_DEGREE 4

bool cmc_no_cache::Recorder::train_entry(champsim::block_number block_addr)
{
  if (index == 0)
  {
      // first entry
      assert(entry_empty());
      entries.push_back(block_addr);
      index++;
      return false;
  }

  assert(!entry_empty());
  // enqueue entry
  if (index >= nr_entry)
  {
    // entry full
    entries.push_back(block_addr);
    index++;
    return true;
  } 
  else 
  {
    entries.push_back(block_addr);
    index++;
    return false;
  }
}

void cmc_no_cache::Recorder::reset()
{
    index = 0;
    entries.clear();
}

uint64_t cmc_no_cache::metadata_addr(champsim::address ip, champsim::block_number block_addr)
{
  return (ip.to<uint64_t>() << 6) ^ (block_addr.to<uint64_t>() << 6);
}

uint32_t cmc_no_cache::metadata_set(uint64_t metadata_addr)
{
  return (metadata_addr >> LOG2_BLOCK_SIZE) & (metadata_sets - 1);
}

cmc_no_cache::StorageEntry* cmc_no_cache::find_entry(uint64_t search_addr)
{
  uint32_t set_idx = metadata_set(search_addr);

  for (auto& entry : storage[set_idx])
  {
    if (entry.valid && entry.addr == search_addr)
      return &entry;
  }

  return nullptr;
}

cmc_no_cache::StorageEntry* cmc_no_cache::access_entry(uint64_t addr)
{
  StorageEntry* entry = find_entry(addr);

  if (entry != nullptr)
  {
    if (entry->brrip_info > 0)
      entry->brrip_info -= 1;
  }

  return entry;
}

cmc_no_cache::StorageEntry* cmc_no_cache::find_victim(uint64_t addr)
{
  uint32_t set_idx = metadata_set(addr);
  auto& set = storage[set_idx];

  for (auto& entry : set)
  {
    if (!entry.valid)
      return &entry; 
  }

  while (true) {
    for (auto& entry : set) {
      if (entry.brrip_info >= 3)
        return &entry;
    }

    for (auto& entry : set)
      entry.brrip_info += 1;
  }

  return nullptr;
}

void cmc_no_cache::prefetcher_initialize()
{
  CACHE* cache = this->intern_;
  metadata_ways = cache->NUM_WAY;
  metadata_sets = cache->NUM_SET;
  recorder = new Recorder(degree);
  storage = std::vector<std::vector<StorageEntry>>(metadata_sets, std::vector<StorageEntry>(metadata_ways));
}

uint32_t cmc_no_cache::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in, bool late_prefetch, bool prefetch_from_this)
{
  // Make sure it's a load
  champsim::block_number block_addr(addr);
  if( type != access_type::LOAD || block_addr == champsim::block_number(0) )
    return metadata_in;

  // bool covered = false;
  bool covered = (cache_hit || late_prefetch) && !prefetch_from_this;

  // Attempt Prediction
  uint64_t current_addr = metadata_addr(ip, block_addr);
  StorageEntry* match_entry = find_entry(current_addr);

  // printf("Load %lx Hit %u Late %u This %u Covered %u\n", block_addr.to<uint64_t>(), (bool)cache_hit, late_prefetch, prefetch_from_this, covered);
  // printf("Send Load: %lx %lx\n", addr.to<uint64_t>(), current_addr);

  if ( !covered && match_entry )
  {
    // printf("Prefetch From %lx\n", current_addr);
    access_entry(current_addr);
    for (auto pref_block: match_entry->addresses) {
      // printf("Prefetch %lx %lx\n", pref_block.to<uint64_t>(), ip.to<uint64_t>());
      prefetch_line(champsim::address(pref_block), true, 0 /*prefetch_metadata*/, ip);
    }
  } 
  else if ( match_entry )
  {
    // printf("Invalidate %lx\n", current_addr);
    match_entry->valid = false;
  }

  // Update Recorder
  bool train_trigger = (trigger.size() < 1 || match_entry) && trigger.size() < trigger_buffer_size && !covered;
  if (train_trigger) {
    trigger.push_back(RecordEntry(ip, block_addr));
  }

  bool do_training = !train_trigger && !trigger.empty() && !covered;
  if (do_training) {
    bool finished = recorder->train_entry(block_addr);
    auto &trigger_head = trigger.front();

    if (finished)
    {
      uint64_t trigger_addr = metadata_addr(trigger_head.pc, trigger_head.block_addr);
      StorageEntry* entry = find_entry(trigger_addr);

      if (entry)
      {
        // printf("Update Block %lx\n", trigger_addr);
        entry->addresses = recorder->entries;
      } 
      else 
      {
        // printf("Fill Block %lx\n", trigger_addr);
        entry = find_victim(trigger_addr);
        entry->valid = true;
        entry->addr = trigger_addr;
        entry->brrip_info = 3;

        access_entry(trigger_addr);
        entry->addresses = recorder->entries;
      }

      trigger.pop_front();
      recorder->reset();
    }
  }

  return metadata_in;
}
