#include "cache.h"

#include "cmc_revision_1.h"

#include <iostream>

bool cmc_revision_1::Recorder::train_entry(champsim::block_number block_addr)
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

void cmc_revision_1::Recorder::reset()
{
    index = 0;
    entries.clear();
}

champsim::address cmc_revision_1::metadata_addr(champsim::address ip, champsim::block_number block_addr)
{
  return champsim::address(block_addr.to<uint64_t>() << LOG2_BLOCK_SIZE);
}

void cmc_revision_1::prefetcher_initialize()
{
  cache = this->intern_;
  recorder = new Recorder(degree);
}

uint32_t cmc_revision_1::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in, bool late_prefetch, bool prefetch_from_this)
{
  // Don't prefetch metadata
  if (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE)
    return metadata_in;

  // Make sure it's a load
  champsim::block_number block_addr(addr);
  if(type != access_type::LOAD || block_addr == champsim::block_number(0))
    return metadata_in;

  bool covered = (cache_hit || late_prefetch) && !prefetch_from_this;

  if (!covered) cache->metadata_load(metadata_addr(ip, block_addr), ip, 0 /*cpu*/, std::make_shared<CMCRequest>(CMCRequest::request_type::LOAD, ip, block_addr, covered));

  return metadata_in;
}

void cmc_revision_1::prefetcher_metadata_request_fill(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());

  assert(cmc_request.type == CMCRequest::request_type::STORE);

  blk = std::make_shared<CMCBlock>(cmc_request.entries);
}

void cmc_revision_1::prefetcher_metadata_request_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk, bool hit)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());

  if (cmc_request.type == CMCRequest::request_type::LOAD)
  {
    if (hit)
    {
      assert(blk != nullptr);

      CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());

      for (auto pf_block: cmc_blk.addresses)
      {
        prefetch_line(champsim::address(pf_block), true, 0 /*prefetch_metadata*/, cmc_request.pc);
      }
    }

    bool train_trigger = (trigger.size() < 1 || hit) && trigger.size() < trigger_buffer_size;
    if (train_trigger) {
      trigger.push_back(RecordEntry(cmc_request.pc, cmc_request.block_addr));
    }

    bool do_training = !train_trigger && !trigger.empty();
    if (do_training) {
      bool finished = recorder->train_entry(cmc_request.block_addr);
      auto &trigger_head = trigger.front();

      if (finished)
      {
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
      assert(blk != nullptr);
      blk = std::make_shared<CMCBlock>(cmc_request.entries);
    }
  }
}

void cmc_revision_1::prefetcher_metadata_simulate_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk, std::vector<champsim::address>& prefetch_addresses, bool hit)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());
  assert(cmc_request.type == CMCRequest::request_type::LOAD);

  if (hit)
  {
    assert(blk != nullptr);
    CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());
    for (auto pf_block: cmc_blk.addresses)
      prefetch_addresses.push_back(champsim::address(pf_block));
  }
}