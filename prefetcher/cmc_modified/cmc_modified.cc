#include "cache.h"

#include "cmc_modified.h"

#include <iostream>

bool cmc_modified::Recorder::train_entry(champsim::block_number block_addr)
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

void cmc_modified::Recorder::reset()
{
    index = 0;
    entries.clear();
}

champsim::address cmc_modified::metadata_addr(champsim::address ip, champsim::block_number block_addr)
{
  return champsim::address(/*(ip.to<uint64_t>() << 6) ^*/ (block_addr.to<uint64_t>() << 6));
}

void cmc_modified::send_metadata_load(champsim::address ip, champsim::block_number block_addr, bool covered)
{
  request_type packet;

  packet.address = metadata_addr(ip, block_addr);
  packet.v_address = metadata_addr(ip, block_addr);
  packet.cpu = this->cache->cpu;
  packet.instr_id = 0;
  packet.ip = ip;
  packet.type = access_type::METADATA_LOAD;
  packet.metadata = true;
  packet.metadata_request = std::make_shared<CMCRequest>(CMCRequest::request_type::LOAD, ip, block_addr, covered);

  this->cache_channel.add_rq(packet);
}

void cmc_modified::send_metadata_store(champsim::address ip, champsim::block_number block_addr, std::vector<champsim::block_number> entries)
{
  request_type packet;

  packet.address = metadata_addr(ip, block_addr);
  packet.v_address = metadata_addr(ip, block_addr);
  packet.cpu = this->cache->cpu;
  packet.instr_id = 0;
  packet.ip = ip;
  packet.type = access_type::METADATA_STORE;
  packet.metadata = true;
  packet.metadata_request = std::make_shared<CMCRequest>(CMCRequest::request_type::STORE, ip, block_addr, entries);

  this->cache_channel.add_wq(packet);
}

void cmc_modified::prefetcher_initialize()
{
  cache = this->intern_;
  this->cache->upper_levels.push_back(&this->cache_channel);
  recorder = new Recorder(degree);
}

uint32_t cmc_modified::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in, bool late_prefetch, bool prefetch_from_this)
{
  // Don't prefetch metadata
  if (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE)
    return metadata_in;

  // Make sure it's a load
  champsim::block_number block_addr(addr);
  if(type != access_type::LOAD || block_addr == champsim::block_number(0))
    return metadata_in;

  bool covered = (cache_hit || late_prefetch) && !prefetch_from_this;

  // Attempt Prediction
  send_metadata_load(ip, block_addr, covered);

  return metadata_in;
}

void cmc_modified::prefetcher_cycle_operate()
{
  // Clear Channel If Response Exists
  while (!this->cache_channel.returned.empty()) {
    auto response = this->cache_channel.returned.front();
    this->cache_channel.returned.pop_front();
  }
}

void cmc_modified::prefetcher_metadata_request_fill(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());

  assert(cmc_request.type == CMCRequest::request_type::STORE);

  // printf("Fill Block %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
  blk = std::make_shared<CMCBlock>(cmc_request.entries);
}

void cmc_modified::prefetcher_metadata_request_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk> blk, bool hit)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());

  if (cmc_request.type == CMCRequest::request_type::LOAD)
  {
    if (hit)
    {
      if (cmc_request.covered)
      {
        // printf("Invalidate %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
        // cache->invalidate_entry(metadata_addr(cmc_request.pc, cmc_request.block_addr), true /*metadata*/);
      }
      else
      {
        CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());

        // printf("Prefetch From %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
        for (auto pf_block: cmc_blk.addresses)
          prefetch_line(champsim::address(pf_block), true, 0 /*prefetch_metadata*/, cmc_request.pc);
      }
    }

    bool train_trigger = (trigger.size() < 1 || hit) && trigger.size() < trigger_buffer_size;
    if (train_trigger) {
      trigger.push_back(RecordEntry(cmc_request.pc, cmc_request.block_addr));
    }

    bool do_training = !train_trigger && !trigger.empty() && !cmc_request.covered;
    if (do_training) {
      bool finished = recorder->train_entry(cmc_request.block_addr);
      auto &trigger_head = trigger.front();

      if (finished)
      {
        send_metadata_store(trigger_head.pc, trigger_head.block_addr, recorder->entries);
        trigger.pop_front();
        recorder->reset();
      }
    }
  }
  else if (cmc_request.type == CMCRequest::request_type::STORE)
  {
    if (hit) // Misses handled by fill logic
    {
      // printf("Update Block %lx\n", metadata_addr(cmc_request.pc, cmc_request.block_addr).to<uint64_t>());
      blk = std::make_shared<CMCBlock>(cmc_request.entries);
    }
  }
}
