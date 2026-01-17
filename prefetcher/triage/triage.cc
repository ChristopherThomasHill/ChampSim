#include "cache.h"

#include "triage.h"

void triage::prefetcher_initialize()
{
  cache = this->intern_;

  this->cache->upper_levels.push_back(&this->cache_channel);
}

uint32_t triage::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                      uint32_t metadata_in)
{
  // Don't prefetch metadata
  if (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE) {
    return metadata_in;
  }

  request_type packet;

  packet.address = champsim::address{0x1000};
  packet.v_address = champsim::address{0x1000};
  packet.cpu = this->cache->cpu;
  packet.instr_id = 0;
  packet.ip = champsim::address(0);
  packet.type = access_type::METADATA_LOAD;
  packet.metadata = true;

  bool success = this->cache_channel.add_rq(packet);

  printf("Sent Packet %u\n", success);

  return metadata_in;
}

uint32_t triage::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  return metadata_in;
}

void triage::prefetcher_cycle_operate()
{
  while (!this->cache_channel.returned.empty()) {
    auto response = this->cache_channel.returned.front();
    this->cache_channel.returned.pop_front();
    printf("Received data for addr: %lx\n", response.address);
  }
}

void triage::prefetcher_final_stats()
{

}