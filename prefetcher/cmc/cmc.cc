#include "cache.h"

#include "cmc.h"

#include <iostream>

#define MAX_DEGREE 4

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
  return champsim::address((ip.to<uint64_t>() << 6) ^ (block_addr.to<uint64_t>() << 6));
}

void cmc::send_metadata_load(champsim::address ip, champsim::block_number block_addr, bool covered)
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

  /*bool success =*/ this->cache_channel.add_rq(packet);
  
  // if (success)
  //   printf("Sent Load address:%lx ip:%lx block_addr:%lx\n", metadata_addr(ip, block_addr).to<uint64_t>(), ip.to<uint64_t>(), block_addr.to<uint64_t>());
}

void cmc::send_metadata_store(champsim::address ip, champsim::block_number block_addr, std::vector<champsim::block_number> entries)
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

  /*bool success =*/ this->cache_channel.add_wq(packet);

  // if (success)
    // printf("Sent Store address:%lx ip:%lx block_addr:%lx\n", metadata_addr(ip, block_addr).to<uint64_t>(), ip.to<uint64_t>(), block_addr.to<uint64_t>());
}

void cmc::prefetcher_initialize()
{
  cache = this->intern_;
  this->cache->upper_levels.push_back(&this->cache_channel);
  recorder = new Recorder(degree);
}

uint32_t cmc::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in)
{
  // Don't prefetch metadata
  if (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE) {
    return metadata_in;
  }

  // Make sure it's a load
  champsim::block_number block_addr(addr);
  if(type != access_type::LOAD || block_addr == champsim::block_number(0)) {
    return metadata_in;
  }

  bool covered = cache_hit;

  // Attempt Prediction
  send_metadata_load(ip, block_addr, covered);

  return metadata_in;
}

uint32_t cmc::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  return metadata_in;
}

void cmc::prefetcher_cycle_operate()
{
  // Clear Channel If Response Exists
  while (!this->cache_channel.returned.empty()) {
    auto response = this->cache_channel.returned.front();
    this->cache_channel.returned.pop_front();
  }
}

void cmc::prefetcher_final_stats()
{

}

void cmc::prefetcher_metadata_request_fill(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk>& blk)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());
  // printf("Request Fill %u %lx %lx\n", cmc_request.type, cmc_request.pc.to<uint64_t>(), cmc_request.block_addr.to<uint64_t>());

  assert(cmc_request.type == CMCRequest::request_type::STORE);

  blk = std::make_shared<CMCBlock>();
  CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());

  cmc_blk.addresses = cmc_request.entries;
}

void cmc::prefetcher_metadata_request_update(const std::shared_ptr<champsim::MetadataRequest>& request, std::shared_ptr<champsim::MetadataBlk> blk, bool hit)
{
  CMCRequest& cmc_request = *static_cast<CMCRequest*>(request.get());
  // printf("Request Update %u %lx %lx %u %u\n", cmc_request.type, cmc_request.pc.to<uint64_t>(), cmc_request.block_addr.to<uint64_t>(), cmc_request.covered, hit);

  if (cmc_request.type == CMCRequest::request_type::LOAD)
  {
    if (hit)
    {
      if (!cmc_request.covered)
      {
        cache->invalidate_entry(metadata_addr(cmc_request.pc, cmc_request.block_addr), true /*metadata*/);
      }
      else 
      {
        CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());

        for (auto pf_block: cmc_blk.addresses) {
          prefetch_line(champsim::address(pf_block), true, 0 /*prefetch_metadata*/);
        }
      }
    }

    bool train_trigger = (trigger.size() < 1 || hit) && trigger.size() < trigger_buffer_size;
    if (train_trigger) {
      assert(cmc_request.pc.to<uint64_t>() != 0 && cmc_request.block_addr.to<uint64_t>() != 0);
      trigger.push_back(RecordEntry(cmc_request.pc, cmc_request.block_addr));
    }

    bool do_training = !train_trigger && !trigger.empty() && !cmc_request.covered;
    if (do_training) {
      bool finished = recorder->train_entry(cmc_request.block_addr);
      auto &trigger_head = trigger.front();
      assert(trigger_head.pc.to<uint64_t>() != 0 && trigger_head.block_addr.to<uint64_t>() != 0);

      if (finished)
      {
        assert(trigger.size() != 0);
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
      CMCBlock& cmc_blk = *static_cast<CMCBlock*>(blk.get());
      cmc_blk.addresses = cmc_request.entries;
    }
  }
}
