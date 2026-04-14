#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>

#include "champsim.h"
#include "mockingjay_weight_adj_4.h"

bool mockingjay_weight_adj_4::is_sampled_set(long set)
{
  long mask_length = LOG2_LLC_SET - LOG2_SAMPLED_SETS;
  long mask = (1 << mask_length) - 1;
  return (set & mask) == ((set >> (LOG2_LLC_SET - mask_length)) & mask);
}

uint64_t mockingjay_weight_adj_4::CRC_HASH(uint64_t _blockAddress)
{
  static const unsigned long long crcPolynomial = 3988292384ULL;
  unsigned long long _returnVal = _blockAddress;
  for( unsigned int i = 0; i < 3; i++)
      _returnVal = ( ( _returnVal & 1 ) == 1 ) ? ( ( _returnVal >> 1 ) ^ crcPolynomial ) : ( _returnVal >> 1 );
  return _returnVal;
}

uint64_t mockingjay_weight_adj_4::build_signature(uint32_t triggering_cpu, champsim::address ip, access_type type, uint8_t hit)
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

uint64_t mockingjay_weight_adj_4::get_sampled_cache_index(uint64_t full_addr)
{
  full_addr = full_addr >> LOG2_BLOCK_SIZE;
  full_addr = (full_addr << (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET))) >> (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET));
  return full_addr;
}

uint64_t mockingjay_weight_adj_4::get_sampled_cache_tag(uint64_t x)
{
  x >>= LOG2_LLC_SET + LOG2_BLOCK_SIZE + LOG2_SAMPLED_CACHE_SETS;
  x = (x << (64 - SAMPLED_CACHE_TAG_BITS)) >> (64 - SAMPLED_CACHE_TAG_BITS);
  return x;
}

uint64_t mockingjay_weight_adj_4::get_prefetch_sampled_cache_index(uint64_t full_addr)
{
  full_addr = full_addr >> LOG2_BLOCK_SIZE;
  full_addr = (full_addr << (64 - LOG2_PREFETCH_SAMPLED_CACHE_SETS)) >> (64 - LOG2_PREFETCH_SAMPLED_CACHE_SETS);
  return full_addr;
}

uint64_t mockingjay_weight_adj_4::get_prefetch_sampled_cache_tag(uint64_t x)
{
  x >>= LOG2_BLOCK_SIZE + LOG2_PREFETCH_SAMPLED_CACHE_SETS;
  x = (x << (64 - SAMPLED_CACHE_TAG_BITS)) >> (64 - SAMPLED_CACHE_TAG_BITS);
  return x;
}

int mockingjay_weight_adj_4::search_sampled_cache(uint64_t blockAddress, bool metadata, uint32_t set)
{
  SampledCacheLine* sampled_set = metadata ? metadata_sampled_cache[set] : data_sampled_cache[set];
  for (int way = 0; way < SAMPLED_CACHE_WAYS; way++) {
      if (sampled_set[way].valid && (sampled_set[way].tag == blockAddress)) {
          return way;
      }
  }
  return -1;
}

int mockingjay_weight_adj_4::search_prefetch_sampled_cache(uint64_t blockAddress, uint32_t set)
{
  SampledCacheLine* sampled_set = prefetch_sampled_cache[set];
  for (int way = 0; way < PREFETCH_SAMPLED_CACHE_WAYS; way++)
  {
      if (sampled_set[way].valid && (sampled_set[way].tag == blockAddress))
      {
        return way;
      }
  }
  return -1;
}

void mockingjay_weight_adj_4::detrain(uint32_t set, int way, bool metadata)
{
  std::unordered_map<uint64_t, SampledCacheLine*>& sampled_cache = metadata ? metadata_sampled_cache : data_sampled_cache;

  SampledCacheLine temp = sampled_cache[set][way];
  if (!temp.valid) {
      return;
  }

  if (rdp.count(temp.signature)) {
      rdp[temp.signature] = std::min(rdp[temp.signature] + 1, INF_RD);
  } else {
      rdp[temp.signature] = INF_RD;
  }
  assert(rdp[temp.signature] <= INF_RD);
  sampled_cache[set][way].valid = false;
}

void mockingjay_weight_adj_4::prefetch_detrain(uint32_t set, int way)
{
  SampledCacheLine temp = prefetch_sampled_cache[set][way];
  if (!temp.valid) return;

  accuracy_samples[temp.signature] += 1;
  if (accuracy_samples[temp.signature] >= METADATA_SHIFT_ACCURACY)
  {
    printf("Shifting Signature %lu Accuracy %.6f\n", temp.signature, static_cast<double>(accuracy_hits[temp.signature]) / accuracy_samples[temp.signature]);

    accuracy_hits[temp.signature] >>= 1;
    accuracy_samples[temp.signature] >>= 1;
  }
  assert(accuracy_hits[temp.signature] >= 0);
  assert(accuracy_samples[temp.signature] > 0);
  prefetch_sampled_cache[set][way].valid = false;
}

int mockingjay_weight_adj_4::temporal_difference(int init, int sample)
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

int mockingjay_weight_adj_4::increment_timestamp(int input)
{
  input++;
  input = input % (1 << TIMESTAMP_BITS);
  return input;
}

int mockingjay_weight_adj_4::time_elapsed(int global, int local)
{
  if (global >= local) {
    return global - local;
  }

  global = global + (1 << TIMESTAMP_BITS);
  return global - local;
}

int mockingjay_weight_adj_4::prefetch_time_elapsed(int local)
{
  if (prefetch_current_timestamp >= local) {
    return prefetch_current_timestamp - local;
  }

  return prefetch_current_timestamp + (1 << PREFETCH_TIMESTAMP_BITS) - local;
}

mockingjay_weight_adj_4::mockingjay_weight_adj_4(CACHE* _cache) : mockingjay_weight_adj_4(_cache, _cache->NUM_SET, _cache->NUM_WAY) {}

mockingjay_weight_adj_4::mockingjay_weight_adj_4(CACHE* _cache, long sets, long ways) 
                    : replacement(_cache),
                      cache(_cache),
                      NUM_SET(sets),
                      NUM_WAY(ways),
                      LOG2_LLC_SET(std::log2(NUM_SET)),
                      LOG2_LLC_SIZE(LOG2_LLC_SET + std::log2(NUM_WAY) + LOG2_BLOCK_SIZE),
                      LOG2_SAMPLED_SETS(LOG2_LLC_SIZE - 16),
                      HISTORY(8),
                      GRANULARITY(8),
                      METADATA_HISTORY(40),
                      METADATA_GRANULARITY(METADATA_HISTORY * GRANULARITY / HISTORY),
                      INF_RD(NUM_WAY * HISTORY - 1),
                      INF_ETR((NUM_WAY * HISTORY / GRANULARITY) - 1),
                      MAX_RD(INF_RD - 22),
                      METADATA_HISTORY_RATIO(METADATA_HISTORY / HISTORY),
                      SAMPLED_CACHE_WAYS(5),
                      LOG2_SAMPLED_CACHE_SETS(4),
                      SAMPLED_CACHE_TAG_BITS(31 - LOG2_LLC_SIZE),
                      PC_SIGNATURE_BITS(LOG2_LLC_SIZE - 10),
                      TIMESTAMP_BITS(11),
                      TEMP_DIFFERENCE(1.0/16.0),
                      FLEXMIN_PENALTY(2.0 - std::log2(NUM_CPUS)/4.0),
                      PREFETCH_SAMPLE_HISTORY(2),
                      PREFETCH_SAMPLED_CACHE_WAYS(4),
                      LOG2_PREFETCH_SAMPLED_CACHE_SETS(8),
                      PREFETCH_SAMPLED_CACHE_INF(PREFETCH_SAMPLE_HISTORY * NUM_WAY * (1 << LOG2_SAMPLED_CACHE_SETS)),
                      PREFETCH_TIMESTAMP_BITS(12),
                      METADATA_SHIFT_ACCURACY(512),
                      METADATA_USELESS_ACCURACY(0.125),
                      reuse_profiler(sets),
                      mockingjay_profiler(sets, ways, INF_ETR)
{
  assert(HISTORY / GRANULARITY == METADATA_HISTORY / METADATA_GRANULARITY);

  etr = std::vector<std::vector<int>>(NUM_SET, std::vector<int>(NUM_WAY));
  metadata_sig = std::vector<std::vector<uint64_t>>(NUM_SET, std::vector<uint64_t>(NUM_WAY));
  etr_clock = std::vector<int>(NUM_SET, GRANULARITY);
  metadata_etr_clock = std::vector<int>(NUM_SET, METADATA_GRANULARITY);
  current_timestamp = std::vector<int>(NUM_SET, 0);
  prefetch_current_timestamp = 0;

  for(uint32_t set = 0; set < NUM_SET; set++)
  {
    if (is_sampled_set(set)) {
      int modifier = 1 << LOG2_LLC_SET;
      int limit = 1 << LOG2_SAMPLED_CACHE_SETS;
      for (int i = 0; i < limit; i++)
      {
        data_sampled_cache[set + modifier*i] = new SampledCacheLine[SAMPLED_CACHE_WAYS]();
        metadata_sampled_cache[set + modifier*i] = new SampledCacheLine[SAMPLED_CACHE_WAYS]();
      }
    }
  }

  for (uint32_t set = 0; set < (1u << LOG2_PREFETCH_SAMPLED_CACHE_SETS); set++)
  {
    prefetch_sampled_cache[set] = new SampledCacheLine[PREFETCH_SAMPLED_CACHE_WAYS]();
  }
}

long mockingjay_weight_adj_4::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type)
{
  assert(type != access_type::METADATA_LOAD);

  for (uint32_t way = 0; way < NUM_WAY; way++) {
    if (current_set[way].valid == false) {
      return way;
    }
  }

  // your eviction policy goes here
  double max_etr = 0;
  int victim_way = 0;
  for (uint32_t way = 0; way < NUM_WAY; way++) {

    double way_etr;
    if (metadata_sig[set][way] == METADATA_NO_SIG) way_etr = etr[set][way];
    else if (abs(etr[set][way]) == INF_ETR) way_etr = etr[set][way];
    else if (!accuracy_hits.count(metadata_sig[set][way])) way_etr = INF_ETR;
    else 
    {
      double way_acc = static_cast<double>(accuracy_hits[metadata_sig[set][way]]) / accuracy_samples[metadata_sig[set][way]];
      double comparable_etr = (etr[set][way] + (etr[set][way] >= 0 ? 0.5 : -0.5)) * METADATA_HISTORY_RATIO;
      if (way_acc > 0.875) way_etr = comparable_etr / 18.0; // 14+ Useful (Rest Pollution)
      else if (way_acc > 0.75) way_etr = comparable_etr / 15.0; // 12+ Useful (Rest Pollution)
      else if (way_acc > 0.625) way_etr = comparable_etr / 12.0; // 10+ Useful (Rest Pollution)
      else if (way_acc > 0.5) way_etr = comparable_etr / 9.0; // 8+ Useful (Rest Pollution)
      else if (way_acc > 0.375) way_etr = comparable_etr / 6.0; // 6+ Useful (Rest Pollution)
      else if (way_acc > 0.25) way_etr = comparable_etr / 3.0; // 4+ Useful (Rest Pollution)
      else if (way_acc > 0.125) way_etr = comparable_etr; // 2+ Useful (Rest Pollution)
      else way_etr = INF_ETR;
    }

    if (abs(way_etr) > max_etr ||
          (abs(way_etr) == max_etr &&
            way_etr < 0)) { //TECHNICALLY this logic is not correct. While this does prioritize negative values, it does prioritize negative values over other negative values.
      max_etr = abs(way_etr);
      victim_way = way;
    }
  }
  
  uint64_t pc_signature = build_signature(triggering_cpu, ip, type, false);
  
  if (type == access_type::METADATA_STORE)
  {
    if (!accuracy_hits.count(pc_signature) || (static_cast<double>(accuracy_hits[pc_signature]) / accuracy_samples[pc_signature] <= METADATA_USELESS_ACCURACY))
    {
      mockingjay_profiler.record_bypass(ip, type);
      return NUM_WAY;
    }

    if (!rdp.count(pc_signature) || rdp[pc_signature] > (INF_RD - 10) /*MAX_RD*/)
    {
      mockingjay_profiler.record_bypass(ip, type);
      return NUM_WAY;
    }

    double insert_acc = static_cast<double>(accuracy_hits[pc_signature]) / accuracy_samples[pc_signature];
    double comparable_etr = ((rdp[pc_signature] / GRANULARITY) + 0.5) * METADATA_HISTORY_RATIO;
    double insert_etr;
    if (insert_acc > 0.875) insert_etr = comparable_etr / 18.0; // 14+ Useful (Rest Pollution)
    else if (insert_acc > 0.75) insert_etr = comparable_etr / 15.0; // 12+ Useful (Rest Pollution)
    else if (insert_acc > 0.625) insert_etr = comparable_etr / 12.0; // 10+ Useful (Rest Pollution)
    else if (insert_acc > 0.5) insert_etr = comparable_etr / 9.0; // 8+ Useful (Rest Pollution)
    else if (insert_acc > 0.375) insert_etr = comparable_etr / 6.0; // 6+ Useful (Rest Pollution)
    else if (insert_acc > 0.25) insert_etr = comparable_etr / 3.0; // 4+ Useful (Rest Pollution)
    else if (insert_acc > 0.125) insert_etr = comparable_etr; // 2+ Useful (Rest Pollution)
    else insert_etr = INF_ETR;

    if (insert_etr > max_etr)
    {
      mockingjay_profiler.record_bypass(ip, type);
      return NUM_WAY;
    }
  }
  else
  {
    if (type != access_type::WRITE && rdp.count(pc_signature) &&
            (rdp[pc_signature] > MAX_RD || rdp[pc_signature] / GRANULARITY > max_etr))
    {
      mockingjay_profiler.record_bypass(ip, type);
      return NUM_WAY;
    }
  }
  
  return victim_way;
}

void mockingjay_weight_adj_4::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit, const std::shared_ptr<champsim::MetadataRequest>& meta_request, bool local_pref)
{
  reuse_profiler.track_info(set, full_addr, ip, type, hit);

  if (type == access_type::WRITE)
  {
    assert(way < NUM_WAY);
    int previous_etr = etr[set][way];
    if(!hit)
    {
      etr[set][way] = -1 * INF_ETR;
      metadata_sig[set][way] = METADATA_NO_SIG;
    }
    mockingjay_profiler.record_update(set, way, ip, victim_addr, type, hit, etr[set][way], previous_etr);
    return;
  }
  
  const bool metadata_access = (type == access_type::METADATA_STORE) || (type == access_type::METADATA_LOAD);

  if (!metadata_access)
  {
    uint64_t sampled_cache_index = get_prefetch_sampled_cache_index(full_addr.to<uint64_t>());
    uint64_t sampled_cache_tag = get_prefetch_sampled_cache_tag(full_addr.to<uint64_t>());
    int sampled_cache_way = search_prefetch_sampled_cache(sampled_cache_tag, sampled_cache_index);
    
    if (sampled_cache_way > -1)
    {
      if (local_pref)
      {
        prefetch_sampled_cache[sampled_cache_index][sampled_cache_way].prefetched = true;
      }
      else
      {
        uint64_t last_signature = prefetch_sampled_cache[sampled_cache_index][sampled_cache_way].signature;
        uint64_t last_timestamp = prefetch_sampled_cache[sampled_cache_index][sampled_cache_way].timestamp;
        
        int sample = prefetch_time_elapsed(last_timestamp);
        if (sample < PREFETCH_SAMPLED_CACHE_INF && (prefetch_sampled_cache[sampled_cache_index][sampled_cache_way].prefetched || !hit))
        {
          accuracy_hits[last_signature] += 1;
          accuracy_samples[last_signature] += 1;

          if (accuracy_samples[last_signature] >= METADATA_SHIFT_ACCURACY)
          {
            printf("Shifting Signature %lu Accuracy %.6f\n", last_signature, static_cast<double>(accuracy_hits[last_signature]) / accuracy_samples[last_signature]);
            
            accuracy_hits[last_signature] >>= 1;
            accuracy_samples[last_signature] >>= 1;
          }
        }
        else
        {
          prefetch_detrain(sampled_cache_index, sampled_cache_way);
        }

        prefetch_sampled_cache[sampled_cache_index][sampled_cache_way].valid = false;
      }
    }
  }

  uint64_t signature = build_signature(triggering_cpu, ip, type, hit);  

  if (way < NUM_WAY)
  {
    if (metadata_access)
    {
      metadata_sig[set][way] = signature;
    }
    else
    {
      metadata_sig[set][way] = METADATA_NO_SIG;
    }
  }

  if (is_sampled_set(set))
  {
    uint64_t sampled_cache_index = get_sampled_cache_index(full_addr.to<uint64_t>());
    uint64_t sampled_cache_tag = get_sampled_cache_tag(full_addr.to<uint64_t>());
    int sampled_cache_way = search_sampled_cache(sampled_cache_tag, metadata_access, sampled_cache_index);

    std::unordered_map<uint64_t, SampledCacheLine*>& sampled_cache = metadata_access ? metadata_sampled_cache : data_sampled_cache;

    if (sampled_cache_way > -1)
    {
      uint64_t last_signature = sampled_cache[sampled_cache_index][sampled_cache_way].signature;
      uint64_t last_timestamp = sampled_cache[sampled_cache_index][sampled_cache_way].timestamp;
      int sample = time_elapsed(current_timestamp[set], last_timestamp);

      if (metadata_access) sample = sample / METADATA_HISTORY_RATIO;

      if (sample <= INF_RD)
      {
        if (type == access_type::PREFETCH) sample = sample * FLEXMIN_PENALTY;
        else if (type == access_type::METADATA_STORE) sample = INF_RD;
        
        if (rdp.count(last_signature)) {
          int init = rdp[last_signature];
          rdp[last_signature] = temporal_difference(init, sample);
        } else {
          rdp[last_signature] = std::min(sample, INF_RD);
        }
        assert(rdp[last_signature] <= INF_RD);

        sampled_cache[sampled_cache_index][sampled_cache_way].valid = false;
      }
    }

    int victim_way = sampled_cache_way;
    bool sampled_cache_hit = victim_way > -1;

    champsim::block_number print_addr(full_addr);

    if (type != access_type::METADATA_LOAD || sampled_cache_hit) 
    {
      // Invalidate entry if one isn't available
      {
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
          if (metadata_access) sample = sample / METADATA_HISTORY_RATIO;
          if (sample > INF_RD) {
            lru_way = w;
            lru_rd = INF_RD + 1;
            detrain(sampled_cache_index, w, metadata_access);
          } else if (sample > lru_rd) {
            lru_way = w;
            lru_rd = sample;
          }
        }
        if (!sampled_cache_hit) detrain(sampled_cache_index, lru_way, metadata_access);
      }

      if (!sampled_cache_hit)
      {
        for (int w = 0; w < SAMPLED_CACHE_WAYS; w++)
        {
          if (sampled_cache[sampled_cache_index][w].valid == false)
          {
            victim_way = w;
            break;
          }
        }
      }

      assert(victim_way > -1);

      if ( metadata_access )
      {
        if ( type == access_type::METADATA_STORE )
        {
          cache->impl_prefetcher_metadata_request_fill(meta_request, sampled_cache[sampled_cache_index][victim_way].metadata_blk);
        }
        else
        {
          assert(type == access_type::METADATA_LOAD && sampled_cache_hit);
          assert(sampled_cache[sampled_cache_index][victim_way].metadata_blk != nullptr);

          uint64_t previous_signature = sampled_cache[sampled_cache_index][victim_way].signature;

          std::vector<champsim::address> prefetch_addresses = {};
          cache->impl_prefetcher_metadata_simulate_update(meta_request, sampled_cache[sampled_cache_index][victim_way].metadata_blk, prefetch_addresses, true /*hit*/);

          for (const auto& pref_addr : prefetch_addresses)
          {
            uint64_t prefetch_sampled_cache_index = get_prefetch_sampled_cache_index(pref_addr.to<uint64_t>());
            uint64_t prefetch_sampled_cache_tag = get_prefetch_sampled_cache_tag(pref_addr.to<uint64_t>());
            int prefetch_sampled_cache_way = search_prefetch_sampled_cache(prefetch_sampled_cache_tag, prefetch_sampled_cache_index);

            if (prefetch_sampled_cache_way > -1)
            {
              prefetch_detrain(prefetch_sampled_cache_index, prefetch_sampled_cache_way);
            }

            int lru_way = -1;
            int lru_rd = -1;
            for (int w = 0; w < PREFETCH_SAMPLED_CACHE_WAYS; w++)
            {
              if (prefetch_sampled_cache[prefetch_sampled_cache_index][w].valid == false)
              {
                lru_way = w;
                lru_rd = PREFETCH_SAMPLED_CACHE_INF + 1;
                continue;
              }

              uint64_t last_timestamp = prefetch_sampled_cache[prefetch_sampled_cache_index][w].timestamp;
              int sample = prefetch_time_elapsed(last_timestamp);

              if (sample >= PREFETCH_SAMPLED_CACHE_INF) {
                lru_way = w;
                lru_rd = PREFETCH_SAMPLED_CACHE_INF + 1;
                prefetch_detrain(prefetch_sampled_cache_index, w);
              } else if (sample > lru_rd) {
                lru_way = w;
                lru_rd = sample;
              }
            }
            prefetch_detrain(prefetch_sampled_cache_index, lru_way);

            prefetch_sampled_cache[prefetch_sampled_cache_index][lru_way].valid = true;
            prefetch_sampled_cache[prefetch_sampled_cache_index][lru_way].tag = prefetch_sampled_cache_tag;
            prefetch_sampled_cache[prefetch_sampled_cache_index][lru_way].signature = previous_signature;
            prefetch_sampled_cache[prefetch_sampled_cache_index][lru_way].timestamp = prefetch_current_timestamp;
            prefetch_sampled_cache[prefetch_sampled_cache_index][lru_way].prefetched = false;
          }
        }
      }
      else
      {
        sampled_cache[sampled_cache_index][victim_way].metadata_blk = nullptr;
      }

      // Metadata misses don't exist/aren't useful
      if (type != access_type::METADATA_LOAD || hit) sampled_cache[sampled_cache_index][victim_way].valid = true;
      else sampled_cache[sampled_cache_index][victim_way].valid = false;
      
      sampled_cache[sampled_cache_index][victim_way].signature = signature;
      sampled_cache[sampled_cache_index][victim_way].tag = sampled_cache_tag;
      sampled_cache[sampled_cache_index][victim_way].timestamp = current_timestamp[set];
      
      if ( !metadata_access )
      {
        current_timestamp[set] = increment_timestamp(current_timestamp[set]);
        prefetch_current_timestamp = (prefetch_current_timestamp + 1) % (1 << PREFETCH_TIMESTAMP_BITS);
      }
    }
  }

  if (type == access_type::METADATA_LOAD && !hit) 
  {
    assert(way == NUM_WAY);
    return;
  }

  if (metadata_etr_clock[set] == METADATA_GRANULARITY)
  {
    for (uint32_t w = 0; w < NUM_WAY; w++)
    {
      if ((uint32_t) w != way && abs(etr[set][w]) < INF_ETR && cache->block[set * NUM_WAY + w].metadata) {
        etr[set][w]--;
      }
    }
    metadata_etr_clock[set] = 0;
  }

  if(etr_clock[set] == GRANULARITY)
  {
    for (uint32_t w = 0; w < NUM_WAY; w++)
    {
      if ((uint32_t) w != way && abs(etr[set][w]) < INF_ETR && !cache->block[set * NUM_WAY + w].metadata) {
        etr[set][w]--;
      }
    }
    etr_clock[set] = 0;
  }

  if (!metadata_access)
  {
    metadata_etr_clock[set]++;
    etr_clock[set]++;
  }

  if (way < NUM_WAY) {
    int previous_etr = etr[set][way];

    if(!rdp.count(signature))
    {
      if (NUM_CPUS == 1)
      {
        if (metadata_access) etr[set][way] = INF_ETR;
        else etr[set][way] = 0;
      }
      else
      {
        etr[set][way] = INF_ETR;
      }
    } else {
      etr[set][way] = rdp[signature] / GRANULARITY;
    }

    if (type == access_type::METADATA_LOAD) etr[set][way] = INF_ETR;

    mockingjay_profiler.record_update(set, way, ip, victim_addr, type, hit, etr[set][way], previous_etr);
  }
}

void mockingjay_weight_adj_4::replacement_final_stats()
{
  reuse_profiler.print_profiler(this);
  mockingjay_profiler.print_profiler(this);
}

void mockingjay_weight_adj_4::ReuseProfiler::track_info(long set, champsim::address full_addr, champsim::address ip, access_type type, bool hit)
{
  if (type == access_type::WRITE || type == access_type::TRANSLATION) return;

  champsim::block_number block_num(full_addr);
  const bool metadata_access = (type == access_type::METADATA_LOAD) || (type == access_type::METADATA_STORE);

  TrackerKey key{block_num, metadata_access};

  if (tracker.count(key))
  {
    Signature previous_sig = std::get<2>(tracker[key]);

    if (type == access_type::METADATA_STORE)
    {
      reuse_table[previous_sig].meta_store_after += 1;
    }
    else
    {
      uint64_t reuse_distance = set_age[set] - std::get<0>(tracker[key]);
      if (reuse_distance >= MAX_REUSE)
        reuse_table[previous_sig].no_reuse += 1;
      else if (type == access_type::PREFETCH)
        reuse_table[previous_sig].prefetch_reuse[reuse_distance] += 1;
      else if (type == access_type::METADATA_LOAD)
        reuse_table[previous_sig].metadata_load_reuse[reuse_distance] += 1;
      else
        reuse_table[previous_sig].demand_reuse[reuse_distance] += 1;
    }
  }

  Signature sig = {ip, type, hit};
  tracker[key] = std::make_tuple(set_age[set], set, sig);
  if (!metadata_access) set_age[set] += 1;
}

void mockingjay_weight_adj_4::ReuseProfiler::print_profiler(mockingjay_weight_adj_4* parent)
{
  const std::string& filename = "signature_reuse.csv";

  for (const auto& [key, dataTuple] : tracker)
  {
    const auto& [age, set, sig] = dataTuple;

    if (set_age[set] - age >= MAX_REUSE)
      reuse_table[sig].no_reuse += 1;
  }

  const uint64_t BIN_SIZE = 16;
  const uint64_t NUM_BINS = (MAX_REUSE + 1) / BIN_SIZE;

  struct SortableSig {
    const Signature* sig_ptr;
    const ReuseInfo* info_ptr;
    uint64_t total_count;
  };

  std::vector<SortableSig> sorted_list;

  for (const auto& entry : reuse_table) {
    const Signature& sig = entry.first;
    const ReuseInfo& info = entry.second;

    uint64_t total = 0;

    auto sum_map_total = [&](const std::unordered_map<uint64_t, uint64_t>& m) {
      for (const auto& [dist, count] : m) {
        (void)dist;
        total += count;
      }
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

  std::sort(sorted_list.begin(), sorted_list.end(),
            [](const SortableSig& a, const SortableSig& b) {
              return a.total_count > b.total_count;
            });

  std::ofstream out(filename);
  if (!out.is_open()) {
    std::cerr << "Failed to open reuse profiler output file: " << filename << "\n";
    return;
  }

  out << "PC,AccessType,Hit,Sig,TotalSigSeen,NoReuse,MetaStoreAfter";

  std::string types[] = {"Prefetch", "Demand", "MetaLoad"};

  for (const std::string& type_name : types) {
    for (uint64_t i = 0; i < NUM_BINS; ++i) {
      uint64_t start = i * BIN_SIZE;
      uint64_t end = start + BIN_SIZE - 1;
      out << "," << type_name << "_" << start << "-" << end;
    }
  }
  out << "\n";

  for (const auto& item : sorted_list) {
    const Signature& sig = *item.sig_ptr;
    const ReuseInfo& info = *item.info_ptr;

    out << "0x" << std::hex << sig.ip.to<uint64_t>() << std::dec << ","
        << access_type_names[static_cast<int>(sig.type)] << ","
        << static_cast<int>(sig.hit) << ","
        << parent->build_signature(0 /*assume single core*/, sig.ip, sig.type, sig.hit) << ","
        << item.total_count << ","
        << info.no_reuse << ","
        << info.meta_store_after;

    auto get_bin_sum = [&](const std::unordered_map<uint64_t, uint64_t>& m, uint64_t bin_idx) {
      uint64_t sum = 0;
      uint64_t start = bin_idx * BIN_SIZE;
      for (uint64_t k = 0; k < BIN_SIZE; ++k) {
        auto it = m.find(start + k);
        if (it != m.end()) {
          sum += it->second;
        }
      }
      return sum;
    };

    for (uint64_t i = 0; i < NUM_BINS; ++i)
      out << "," << get_bin_sum(info.prefetch_reuse, i);

    for (uint64_t i = 0; i < NUM_BINS; ++i)
      out << "," << get_bin_sum(info.demand_reuse, i);

    for (uint64_t i = 0; i < NUM_BINS; ++i)
      out << "," << get_bin_sum(info.metadata_load_reuse, i);

    out << "\n";
  }

  out.close();
}

void mockingjay_weight_adj_4::MockingjayProfiler::record_bypass(champsim::address ip, access_type type)
{
  if (type == access_type::WRITE || type == access_type::TRANSLATION) return;

  Signature sig = {ip, type, false /*miss*/};
  bypass_table[sig] += 1;
}

void mockingjay_weight_adj_4::MockingjayProfiler::record_update(long set, long way, champsim::address ip, champsim::address victim_addr, access_type type, bool hit, int insert_etr, int current_etr)
{
  assert((insert_etr <= INF_ETR && insert_etr >= 0) || type == access_type::WRITE);
  assert(current_etr <= INF_ETR && current_etr >= -1 * INF_ETR);
  assert(set >= 0 && set < last_signature.size());
  assert(way >= 0 && way < last_signature[set].size());

  Signature sig = {ip, type, hit};

  if (type != access_type::WRITE && type != access_type::TRANSLATION)
  {
    // Insertion Table
    if (!insertion_etr_table.count(sig)) insertion_etr_table[sig] = std::vector<uint64_t>(INF_ETR + 1, 0);
    insertion_etr_table[sig][insert_etr] += 1;
  }

  bool had_last_sig = last_signature_valid[set][way];
  Signature last_sig = last_signature[set][way];
  last_signature[set][way] = sig;
  last_signature_valid[set][way] = true;

  if (!had_last_sig) return;

  if (last_sig.type == access_type::WRITE || last_sig.type == access_type::TRANSLATION) return; // Write/Translation

  if (hit)
  {
    // Hit Table
    if (!hit_etr_table.count(last_sig)) hit_etr_table[last_sig] = std::vector<uint64_t>(INF_ETR * 2 + 1, 0);
    hit_etr_table[last_sig][current_etr + INF_ETR] += 1;
  }
  else
  {
    if (victim_addr == champsim::address{}) return; // No Previous Signature

    // Eviction Table
    if (!eviction_etr_table.count(last_sig)) eviction_etr_table[last_sig] = std::vector<uint64_t>(INF_ETR * 2 + 1, 0);
    eviction_etr_table[last_sig][current_etr + INF_ETR] += 1;
  }
}

void mockingjay_weight_adj_4::MockingjayProfiler::print_profiler(mockingjay_weight_adj_4* parent)
{
  using CountTable = std::unordered_map<Signature, std::vector<uint64_t>, SignatureKeyHash>;
  constexpr uint64_t MIN_SIGNATURE_COUNT = 30;

  struct SortableSig
  {
    const Signature* sig_ptr;
    const std::vector<uint64_t>* counts_ptr; // can be nullptr for bypass-only insertion rows
    uint64_t total_count;
    uint64_t bypass_count;
  };

  auto vector_total = [](const std::vector<uint64_t>& v) -> uint64_t {
    uint64_t total = 0;
    for (uint64_t x : v)
      total += x;
    return total;
  };

  auto write_insertion_table = [&](const std::string& filename) {
    std::vector<SortableSig> sorted_list;

    // Add signatures that have explicit insertion counts
    for (const auto& entry : insertion_etr_table)
    {
      const Signature& sig = entry.first;
      const std::vector<uint64_t>& counts = entry.second;

      uint64_t total_insertions = vector_total(counts);
      uint64_t bypasses = 0;

      auto bit = bypass_table.find(sig);
      if (bit != bypass_table.end())
        bypasses = bit->second;

      uint64_t total_seen = total_insertions + bypasses;
      if (total_seen >= MIN_SIGNATURE_COUNT)
        sorted_list.push_back({&sig, &counts, total_insertions, bypasses});
    }

    // Add signatures that only ever bypassed
    for (const auto& entry : bypass_table)
    {
      const Signature& sig = entry.first;
      uint64_t bypasses = entry.second;

      if (!insertion_etr_table.count(sig) && bypasses >= MIN_SIGNATURE_COUNT)
        sorted_list.push_back({&sig, nullptr, 0, bypasses});
    }

    std::sort(sorted_list.begin(), sorted_list.end(),
              [](const SortableSig& a, const SortableSig& b) {
                return (a.total_count + a.bypass_count) > (b.total_count + b.bypass_count);
              });

    std::ofstream out(filename);
    if (!out.is_open()) {
      std::cerr << "Failed to open Mockingjay insertion profiler output file: "
                << filename << "\n";
      return;
    }

    out << "PC,AccessType,Hit,Sig,TotalInsertions,Bypasses,TotalSeen";
    for (int etr = 0; etr <= INF_ETR; ++etr)
      out << ",ETR_" << etr;
    out << "\n";

    for (const auto& item : sorted_list)
    {
      const Signature& sig = *item.sig_ptr;
      uint64_t total_seen = item.total_count + item.bypass_count;

      out << "0x" << std::hex << sig.ip.to<uint64_t>() << std::dec << ","
          << access_type_names[static_cast<int>(sig.type)] << ","
          << static_cast<int>(sig.hit) << ","
          << parent->build_signature(0 /*assume single core*/, sig.ip, sig.type, sig.hit) << ","
          << item.total_count << ","
          << item.bypass_count << ","
          << total_seen;

      for (int etr = 0; etr <= INF_ETR; ++etr)
      {
        uint64_t count = 0;
        if (item.counts_ptr != nullptr)
          count = (*(item.counts_ptr))[etr];

        out << "," << count;
      }

      out << "\n";
    }

    out.close();
  };

  auto write_shifted_table = [&](const CountTable& table,
                                 const std::string& filename,
                                 const std::string& total_name) {
    std::vector<SortableSig> sorted_list;

    for (const auto& entry : table)
    {
      const Signature& sig = entry.first;
      const std::vector<uint64_t>& counts = entry.second;

      uint64_t total = vector_total(counts);
      if (total >= MIN_SIGNATURE_COUNT)
        sorted_list.push_back({&sig, &counts, total, 0});
    }

    std::sort(sorted_list.begin(), sorted_list.end(),
              [](const SortableSig& a, const SortableSig& b) {
                return a.total_count > b.total_count;
              });

    std::ofstream out(filename);
    if (!out.is_open()) {
      std::cerr << "Failed to open Mockingjay profiler output file: "
                << filename << "\n";
      return;
    }

    out << "PC,AccessType,Hit,Sig," << total_name;
    for (int etr = -INF_ETR; etr <= INF_ETR; ++etr)
      out << ",ETR_" << etr;
    out << "\n";

    for (const auto& item : sorted_list)
    {
      const Signature& sig = *item.sig_ptr;
      const std::vector<uint64_t>& counts = *item.counts_ptr;

      out << "0x" << std::hex << sig.ip.to<uint64_t>() << std::dec << ","
          << access_type_names[static_cast<int>(sig.type)] << ","
          << static_cast<int>(sig.hit) << ","
          << parent->build_signature(0 /*assume single core*/, sig.ip, sig.type, sig.hit) << ","
          << item.total_count;

      for (std::size_t idx = 0; idx < counts.size(); ++idx)
        out << "," << counts[idx];

      out << "\n";
    }

    out.close();
  };

  write_insertion_table("mockingjay_insertions.csv");
  write_shifted_table(hit_etr_table, "mockingjay_hits.csv", "TotalHits");
  write_shifted_table(eviction_etr_table, "mockingjay_evictions.csv", "TotalEvictions");
}
