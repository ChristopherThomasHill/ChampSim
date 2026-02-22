#include "cache.h"

#include "cmc.h"

#include <iostream>

bool cmc::Recorder::train_entry(champsim::block_number block_addr)
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

void cmc::Recorder::reset()
{
    index = 0;
    entries.clear();
}

champsim::address cmc::metadata_addr(champsim::address ip, champsim::block_number block_addr)
{
  return champsim::address((ip.to<uint64_t>() << LOG2_BLOCK_SIZE) ^ (block_addr.to<uint64_t>() << LOG2_BLOCK_SIZE));
}

void cmc::prefetcher_initialize()
{
  cache = this->intern_;
  recorder = new Recorder(degree);
}

uint32_t cmc::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in, bool late_prefetch, bool prefetch_from_this)
{
  // Don't prefetch metadata
  if (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE)
    return metadata_in;

  // Make sure it's a load
  champsim::block_number block_addr(addr);
  if(type != access_type::LOAD || block_addr == champsim::block_number(0))
    return metadata_in;

  // bool covered = false;
  bool covered = (cache_hit || late_prefetch) && !prefetch_from_this;

  // printf("Load %lx Hit %u\n", block_addr.to<uint64_t>(), (bool)cache_hit);

  // Attempt Prediction
  // if (!cache->warmup) printf("Sent Load Addr: %lx\n", metadata_addr(ip, block_addr).to<uint64_t>());
  // printf("Send Load: %lx %lx\n", addr.to<uint64_t>(), metadata_addr(ip, block_addr).to<uint64_t>());
  // printf("Load %lx Hit %u Late %u This %u Covered %u\n", block_addr.to<uint64_t>(), (bool)cache_hit, late_prefetch, prefetch_from_this, covered);
  cache->metadata_load(metadata_addr(ip, block_addr), ip, 0 /*cpu*/, std::make_shared<CMCRequest>(CMCRequest::request_type::LOAD, ip, block_addr, covered));

  return metadata_in;
}

void cmc::prefetcher_metadata_request_fill(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());

  assert(cmc_request.type == CMCRequest::request_type::STORE);

  // if (!cache->warmup) printf("Receive Store Addr: %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());

  // printf("Fill Block %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
  blk = std::make_shared<CMCBlock>(cmc_request.entries);
}

void cmc::prefetcher_metadata_request_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk, bool hit)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());

  if (cmc_request.type == CMCRequest::request_type::LOAD)
  {
    // printf("Receive Load Addr: %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
    if (hit)
    {
      assert(blk != nullptr);
      if (cmc_request.covered)
      {
        // printf("Invalidate %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
        cache->invalidate_entry(metadata_addr(cmc_request.pc, cmc_request.block_addr), true /*metadata*/);
      }
      else
      {
        CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());

        // printf("Prefetch From %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
        for (auto pf_block: cmc_blk.addresses)
        {
          // printf("Prefetch %lx %lx\n", pf_block.to<uint64_t>(), cmc_request.pc);
          prefetch_line(champsim::address(pf_block), true, 0 /*prefetch_metadata*/, cmc_request.pc);
        }
      }
    }

    bool train_trigger = (trigger.size() < 1 || hit) && trigger.size() < trigger_buffer_size && !cmc_request.covered;
    if (train_trigger) {
      trigger.push_back(RecordEntry(cmc_request.pc, cmc_request.block_addr));
    }

    bool do_training = !train_trigger && !trigger.empty() && !cmc_request.covered;
    if (do_training) {
      bool finished = recorder->train_entry(cmc_request.block_addr);
      auto &trigger_head = trigger.front();

      if (finished)
      {
        // if (!cache->warmup)  printf("Sent Store Addr: %lx\n", metadata_addr(trigger_head.pc, trigger_head.block_addr).to<uint64_t>());
        cache->metadata_store(metadata_addr(trigger_head.pc, trigger_head.block_addr), trigger_head.pc, 0 /*cpu*/, std::make_shared<CMCRequest>(CMCRequest::request_type::STORE, trigger_head.pc, trigger_head.block_addr, recorder->entries));
        trigger.pop_front();
        recorder->reset();
      }
    }
  }
  else if (cmc_request.type == CMCRequest::request_type::STORE)
  {
    if (hit) // Misses handled by fill logic
    {
      // if (!cache->warmup) printf("Receive Store Addr: %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
      assert(blk != nullptr);
      // printf("Update Block %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
      blk = std::make_shared<CMCBlock>(cmc_request.entries);
    }
  }
}
