#include <cmath>

#include "champsim.h"
#include "mockingjay_weighted.h"

bool mockingjay_weighted::is_sampled_set(long set)
{
  long mask_length = LOG2_LLC_SET - LOG2_SAMPLED_SETS;
  long mask = (1 << mask_length) - 1;
  return (set & mask) == ((set >> (LOG2_LLC_SET - mask_length)) & mask);
}

uint64_t mockingjay_weighted::CRC_HASH(uint64_t _blockAddress)
{
  static const unsigned long long crcPolynomial = 3988292384ULL;
  unsigned long long _returnVal = _blockAddress;
  for( unsigned int i = 0; i < 3; i++)
      _returnVal = ( ( _returnVal & 1 ) == 1 ) ? ( ( _returnVal >> 1 ) ^ crcPolynomial ) : ( _returnVal >> 1 );
  return _returnVal;
}

uint64_t mockingjay_weighted::build_signature(uint32_t triggering_cpu, champsim::address ip, access_type type, uint8_t hit)
{
  uint64_t signature;
  if (NUM_CPUS == 1) 
  {
    signature = ip.to<uint64_t>();

    signature <<= 1;
    if(hit) signature = signature | 1;
    
    signature = signature << 2;
    if (type == access_type::PREFETCH) signature |= 0b01;
    if (type == access_type::METADATA_LOAD) signature |= 0b10;
    if (type == access_type::METADATA_STORE) signature |= 0b11;
    
    signature = CRC_HASH(signature);
    signature = (signature << (64 - PC_SIGNATURE_BITS)) >> (64 - PC_SIGNATURE_BITS);
  } 
  else
  {
      signature = ip.to<uint64_t>();

      signature <<= 1;
      if(hit) signature = signature | 1;

      signature = signature << 2;
      if (type == access_type::PREFETCH) signature = signature | 0b01;
      if (type == access_type::METADATA_LOAD) signature = signature | 0b10;
      if (type == access_type::METADATA_STORE) signature = signature | 0b11;

      signature = signature << 2;
      signature = signature | triggering_cpu;

      signature = CRC_HASH(signature);
      signature = (signature << (64 - PC_SIGNATURE_BITS)) >> (64 - PC_SIGNATURE_BITS);
  }
  return signature;
}

uint64_t mockingjay_weighted::get_sampled_cache_index(uint64_t full_addr)
{
  full_addr = full_addr >> LOG2_BLOCK_SIZE;
  full_addr = (full_addr << (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET))) >> (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET));
  return full_addr;
}

uint64_t mockingjay_weighted::get_sampled_cache_tag(uint64_t x)
{
  x >>= LOG2_LLC_SET + LOG2_BLOCK_SIZE + LOG2_SAMPLED_CACHE_SETS;
  x = (x << (64 - SAMPLED_CACHE_TAG_BITS)) >> (64 - SAMPLED_CACHE_TAG_BITS);
  return x;
}

int mockingjay_weighted::search_sampled_cache(uint64_t blockAddress, bool metadata, uint32_t set)
{
  SampledCacheLine* sampled_set = sampled_cache[set];
  for (int way = 0; way < SAMPLED_CACHE_WAYS; way++) {
      if (sampled_set[way].valid && (sampled_set[way].tag == blockAddress) && (sampled_set[way].metadata == metadata)) {
          return way;
      }
  }
  return -1;
}

void mockingjay_weighted::detrain(uint32_t set, int way)
{
  SampledCacheLine temp = sampled_cache[set][way];
  if (!temp.valid) {
      return;
  }

  if (rdp.count(temp.signature)) {
      rdp[temp.signature] = std::min(rdp[temp.signature] + 1, INF_RD);
  } else {
      rdp[temp.signature] = INF_RD;
  }
  sampled_cache[set][way].valid = false;
}

int mockingjay_weighted::temporal_difference(int init, int sample)
{
  if (sample > init) {
    int diff = sample - init;
    diff = diff * TEMP_DIFFERENCE;
    diff = std::min(1, diff);
    return std::min(init + diff, INF_RD);
  } else if (sample < init) {
    int diff = init - sample;
    diff = diff * TEMP_DIFFERENCE;
    diff = std::min(1, diff);
    return std::max(init - diff, 0);
  } else {
    return init;
  }
}

int mockingjay_weighted::increment_timestamp(int input)
{
  input++;
  input = input % (1 << TIMESTAMP_BITS);
  return input;
}

int mockingjay_weighted::time_elapsed(int global, int local)
{
   if (global >= local) {
      return global - local;
    }
    global = global + (1 << TIMESTAMP_BITS);
    return global - local;
}

mockingjay_weighted::mockingjay_weighted(CACHE* cache) : mockingjay_weighted(cache, cache->NUM_SET, cache->NUM_WAY) {}

mockingjay_weighted::mockingjay_weighted(CACHE* cache, long sets, long ways) 
                    : replacement(cache),
                      NUM_SET(sets),
                      NUM_WAY(ways),
                      LOG2_LLC_SET(std::log2(NUM_SET)),
                      LOG2_LLC_SIZE(LOG2_LLC_SET + std::log2(NUM_WAY) + LOG2_BLOCK_SIZE),
                      LOG2_SAMPLED_SETS(LOG2_LLC_SIZE - 16),
                      HISTORY(8),
                      GRANULARITY(8),
                      INF_RD(NUM_WAY * HISTORY - 1),
                      INF_ETR((NUM_WAY * HISTORY / GRANULARITY) - 1),
                      MAX_RD(INF_RD - 22),
                      SAMPLED_CACHE_WAYS(5),
                      LOG2_SAMPLED_CACHE_SETS(4),
                      SAMPLED_CACHE_TAG_BITS(31 - LOG2_LLC_SIZE),
                      PC_SIGNATURE_BITS(LOG2_LLC_SIZE - 10),
                      TIMESTAMP_BITS(8),
                      TEMP_DIFFERENCE(1.0/16.0),
                      FLEXMIN_PENALTY(2.0 - std::log2(NUM_CPUS)/4.0),
                      recency_cache(2048 /*PREFETCH_ACCURACY_CACHE_SIZE*/),
                      METADATA_ELEMENT_COUNT(16),
                      ACCURACY_TABLE_METADATA_LOAD_SAMPLE(512)
{
  etr = std::vector<std::vector<int>>(NUM_SET, std::vector<int>(NUM_WAY));
  etr_clock = std::vector<int>(NUM_SET, GRANULARITY);
  current_timestamp = std::vector<int>(NUM_SET, 0);

  for(uint32_t set = 0; set < NUM_SET; set++)
  {
    if (is_sampled_set(set)) {
      int modifier = 1 << LOG2_LLC_SET;
      int limit = 1 << LOG2_SAMPLED_CACHE_SETS;
      for (int i = 0; i < limit; i++)
        sampled_cache[set + modifier*i] = new SampledCacheLine[SAMPLED_CACHE_WAYS]();
    }
  }
}

long mockingjay_weighted::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type)
{
  for (uint32_t way = 0; way < NUM_WAY; way++) {
    if (current_set[way].valid == false) {
      return way;
    }
  }

  // your eviction policy goes here
  int max_etr = 0;
  int victim_way = 0;
  for (uint32_t way = 0; way < NUM_WAY; way++) {
    if (abs(etr[set][way]) > max_etr ||
          (abs(etr[set][way]) == max_etr &&
            etr[set][way] < 0)) { //TECHNICALLY this logic is not correct. While this does prioritize negative values, it does prioritize negative values over other negative values.
      max_etr = abs(etr[set][way]);
      victim_way = way;
    }
  }
  
  uint64_t pc_signature = build_signature(triggering_cpu, ip, type, false);
  if (type != access_type::WRITE && rdp.count(pc_signature) &&
          (rdp[pc_signature] > MAX_RD || rdp[pc_signature] / GRANULARITY > max_etr)) {
      return NUM_WAY;
  }
  
  return victim_way;
}

void mockingjay_weighted::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit, bool local_pref)
{
  if (type == access_type::WRITE)
  {
    if(!hit) etr[set][way] = -1 * INF_ETR;
    return;
  }

  // Metadata load misses means no producer
  if (type == access_type::METADATA_LOAD && !hit) return;
  
  if (type != access_type::METADATA_LOAD && type != access_type::METADATA_STORE)
  {
    champsim::block_number block_addr(full_addr);
    auto recency_entry = recency_cache.get(block_addr);

    if (recency_entry && !local_pref && hit)
    {
      // Useful Prefetch
      auto& info = accuracy_table[recency_entry->to<uint64_t>()];
      info.useful_prefetches += 1;

      // printf("Useful Prefetch %lx %lx\n", block_addr.to<uint64_t>(), recency_entry->to<uint64_t>());
    }

    if (type == access_type::PREFETCH && local_pref && !hit)
    {  
      // Start Tracking This Prefetch
      recency_cache.access(block_addr, ip);
    
      // printf("Prefetched %lx %lx\n", block_addr.to<uint64_t>(), ip.to<uint64_t>());
    }
  }
  else if (type == access_type::METADATA_LOAD && hit)
  {
    auto& info = accuracy_table[ip.to<uint64_t>()];

    champsim::block_number block_addr(full_addr);
    // printf("Start Tracking %lx %lx\n", block_addr.to<uint64_t>(), ip.to<uint64_t>());

    info.metadata_loads += 1;
    if (info.metadata_loads >= ACCURACY_TABLE_METADATA_LOAD_SAMPLE)
    {
      info.accuracy = static_cast<double>(info.useful_prefetches) / info.metadata_loads;
      info.metadata_loads = 0;
      info.useful_prefetches = 0;

      printf("IP:%lx Accuracy:%f\n", ip.to<uint64_t>(), info.accuracy);
    }
  }

  uint64_t signature = build_signature(triggering_cpu, ip, type, hit);
  const bool metadata_access = (type == access_type::METADATA_STORE) || (type == access_type::METADATA_LOAD);

  if (is_sampled_set(set))
  {
    uint64_t sampled_cache_index = get_sampled_cache_index(full_addr.to<uint64_t>());
    uint64_t sampled_cache_tag = get_sampled_cache_tag(full_addr.to<uint64_t>());
    int sampled_cache_way = search_sampled_cache(sampled_cache_tag, metadata_access, sampled_cache_index);

    if (sampled_cache_way > -1) {
      uint64_t last_signature = sampled_cache[sampled_cache_index][sampled_cache_way].signature;
      uint64_t last_timestamp = sampled_cache[sampled_cache_index][sampled_cache_way].timestamp;
      int sample = time_elapsed(current_timestamp[set], last_timestamp);

      if (sample <= INF_RD) {
        if (type == access_type::PREFETCH) sample = sample * FLEXMIN_PENALTY;
        else if (type == access_type::METADATA_STORE) sample = 2 * INF_RD;
        
        if (rdp.count(last_signature)) {
          int init = rdp[last_signature];
          rdp[last_signature] = temporal_difference(init, sample);
        } else {
          rdp[last_signature] = sample;
        }

        sampled_cache[sampled_cache_index][sampled_cache_way].valid = false;
      }
    }


    int lru_way = -1;
    int lru_rd = -1;
    for (int w = 0; w < SAMPLED_CACHE_WAYS; w++) {
      if (sampled_cache[sampled_cache_index][w].valid == false) {
        lru_way = w;
        lru_rd = INF_RD + 1;
        continue;
      }

      uint64_t last_timestamp = sampled_cache[sampled_cache_index][w].timestamp;
      int sample = time_elapsed(current_timestamp[set], last_timestamp);
      if (sample > INF_RD) {
        lru_way = w;
        lru_rd = INF_RD + 1;
        detrain(sampled_cache_index, w);
      } else if (sample > lru_rd) {
        lru_way = w;
        lru_rd = sample;
      }
    }
    detrain(sampled_cache_index, lru_way);

    for (int w = 0; w < SAMPLED_CACHE_WAYS; w++) {
      if (sampled_cache[sampled_cache_index][w].valid == false) {
        sampled_cache[sampled_cache_index][w].valid = true;
        sampled_cache[sampled_cache_index][w].signature = signature;
        sampled_cache[sampled_cache_index][w].tag = sampled_cache_tag;
        sampled_cache[sampled_cache_index][w].metadata = metadata_access;
        sampled_cache[sampled_cache_index][w].timestamp = current_timestamp[set];
        break;
      }
    }
    
    if ( !metadata_access ) current_timestamp[set] = increment_timestamp(current_timestamp[set]);
  }

  if(etr_clock[set] == GRANULARITY) {
      for (uint32_t w = 0; w < NUM_WAY; w++) {
          if ((uint32_t) w != way && abs(etr[set][w]) < INF_ETR) {
              etr[set][w]--;
          }
      }
      etr_clock[set] = 0;
  }
  if ( !metadata_access) etr_clock[set]++;
  
  
  if (way < NUM_WAY) {
    if(!rdp.count(signature)) {
      if (NUM_CPUS == 1) {
        etr[set][way] = 0;
      } else {
        etr[set][way] = INF_ETR;
      }
    } else {
      if(rdp[signature] > MAX_RD) {
        etr[set][way] = INF_ETR;
      } else {
        etr[set][way] = rdp[signature] / GRANULARITY;
      }
    }
  }
}
