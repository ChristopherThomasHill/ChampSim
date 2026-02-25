#include <cmath>

#include "champsim.h"
#include "streamline.h"

bool streamline::is_sampled_set(long set)
{
  long mask_length = LOG2_LLC_SET - LOG2_SAMPLED_SETS;
  long mask = (1 << mask_length) - 1;
  return (set & mask) == ((set >> (LOG2_LLC_SET - mask_length)) & mask);
}

uint64_t streamline::CRC_HASH(uint64_t _blockAddress)
{
  static const unsigned long long crcPolynomial = 3988292384ULL;
  unsigned long long _returnVal = _blockAddress;
  for( unsigned int i = 0; i < 3; i++)
      _returnVal = ( ( _returnVal & 1 ) == 1 ) ? ( ( _returnVal >> 1 ) ^ crcPolynomial ) : ( _returnVal >> 1 );
  return _returnVal;
}

uint64_t streamline::build_signature(uint32_t triggering_cpu, champsim::address ip, access_type type, uint8_t hit)
{
  uint64_t signature;
  if (NUM_CPUS == 1) 
  {
    signature = ip.to<uint64_t>();

    signature <<= 1;
    if(hit) signature = signature | 1;
    
    signature = signature << 2;
    if (type == access_type::PREFETCH) signature = signature | 0b01;
    if (type == access_type::METADATA_LOAD) signature = signature | 0b10;
    if (type == access_type::METADATA_STORE) signature = signature | 0b11;
    
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

uint64_t streamline::get_sampled_cache_index(uint64_t full_addr)
{
  full_addr = full_addr >> LOG2_BLOCK_SIZE;
  full_addr = (full_addr << (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET))) >> (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET));
  return full_addr;
}

uint64_t streamline::get_sampled_cache_tag(uint64_t full_addr)
{
  full_addr >>= LOG2_LLC_SET + LOG2_BLOCK_SIZE + LOG2_SAMPLED_CACHE_SETS;
  full_addr = (full_addr << (64 - SAMPLED_CACHE_TAG_BITS)) >> (64 - SAMPLED_CACHE_TAG_BITS);
  return full_addr;
}

int streamline::search_sampled_cache(uint64_t blockAddress, uint32_t set)
{
  SampledCacheLine* sampled_set = sampled_cache[set];
  for (int way = 0; way < SAMPLED_CACHE_WAYS; way++) {
      if (sampled_set[way].valid && (sampled_set[way].tag == blockAddress)) {
          return way;
      }
  }
  return -1;
}

void streamline::detrain(uint32_t set, int way)
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

int streamline::temporal_difference(int init, int sample)
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

int streamline::increment_timestamp(int input)
{
  input++;
  input = input % (1 << TIMESTAMP_BITS);
  return input;
}

int streamline::time_elapsed(int global, int local)
{
   if (global >= local) {
      return global - local;
    }
    global = global + (1 << TIMESTAMP_BITS);
    return global - local;
}

void streamline::update_set_dueling(uint32_t triggering_cpu, long set, champsim::address full_addr, champsim::address ip, access_type type)
{
  if (!is_sampled_set(set)) return;

  auto find_way = [this](SetDuelingCacheLine* ways, champsim::block_number target_block, uint32_t min_way, uint32_t max_way) -> uint32_t
  {
    uint32_t lo = std::max((uint32_t)0, min_way);
    uint32_t hi = std::min<uint32_t>(NUM_WAY, max_way);
    if (lo >= hi)
      return NUM_WAY;

    for (uint32_t w = lo; w < hi; ++w) {
      if (ways[w].valid && ways[w].block_num == target_block) {
        return w;
      }
    }

    return NUM_WAY;
  };

  auto find_victim = [this](uint32_t triggering_cpu, long set, SetDuelingCacheLine* ways, champsim::address ip, access_type type, uint32_t min_way, uint32_t max_way) -> uint32_t
  {
    uint32_t lo = std::min<uint32_t>(std::max<uint32_t>(0u, min_way), NUM_WAY);
    uint32_t hi = std::min<uint32_t>(max_way, NUM_WAY);
    if (lo >= hi)
      return NUM_WAY;

    for (uint32_t way = lo; way < hi; ++way) {
      if (!ways[way].valid) {
        return way;
      }
    }

    int max_etr = 0;
    uint32_t victim_way = lo;

    for (uint32_t way = lo; way < hi; ++way) {
      int e = ways[way].etr;
      int ae = std::abs(e);

      if (ae > max_etr || (ae == max_etr && e < 0)) {
        max_etr = ae;
        victim_way = way;
      }
    }

    uint64_t pc_signature = build_signature(triggering_cpu, ip, type, false);
    if (type != access_type::WRITE && rdp.count(pc_signature) &&
        (rdp[pc_signature] > MAX_RD ||
        rdp[pc_signature] / GRANULARITY > static_cast<uint32_t>(max_etr))) {
      return NUM_WAY;
    }

    return victim_way;
  };

  auto set_etr = [this](SetDuelingCacheLine* ways, long set, uint32_t way, uint32_t triggering_cpu, champsim::address ip, access_type type, bool hit) -> void
  {
    if (type == access_type::WRITE)
    {
      if(!hit) ways[way].etr = -1 * INF_ETR;
      return;
    }

    if(etr_clock[set] == GRANULARITY) {
      for (uint32_t w = 0; w < NUM_WAY; w++) {
        if ((uint32_t) w != way && abs(ways[w].etr) < INF_ETR) {
            ways[w].etr--;
        }
      }
    }

    uint64_t signature = build_signature(triggering_cpu, ip, type, hit);

    if(!rdp.count(signature)) {
      if (NUM_CPUS == 1) {
        ways[way].etr = 0;
      } else {
        ways[way].etr = INF_ETR;
      }
    } else {
      if(rdp[signature] > MAX_RD) {
        ways[way].etr = INF_ETR;
      } else {
        ways[way].etr = rdp[signature] / GRANULARITY;
      }
    }
  };

  bool metadata_access = (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE);

  // half metadata way set
  uint32_t min_way = metadata_access ? 0 : NUM_WAY / 2;
  uint32_t max_way = metadata_access ? NUM_WAY / 2 : NUM_WAY;
  uint32_t way = find_way(half_metadata_cache[set], champsim::block_number(full_addr), min_way, max_way);
  bool hit = way != NUM_WAY;

  if (hit)
  {
    if (metadata_access) 
    {
      half_set_duel_counter += prefetch_set_duel_increment;
      half_metadata_set_duel_counter += 1;
    }
    else
    {
      half_set_duel_counter += 16;
      half_demand_set_duel_counter += 1;
    }
  }
  else
  {
    uint32_t victim_way = find_victim(triggering_cpu, set, half_metadata_cache[set], ip, type, min_way, max_way);
    bool bypassing = victim_way == NUM_WAY;
    if (!bypassing)
    {
      half_metadata_cache[set][victim_way].valid = true;
      half_metadata_cache[set][victim_way].block_num = champsim::block_number(full_addr);
    }
    way = victim_way;
  }

  if (way != NUM_WAY) set_etr(half_metadata_cache[set], set, way, triggering_cpu, ip, type, hit);

  // quarter metadata
  min_way = metadata_access ? 0 : NUM_WAY / 4;
  max_way = metadata_access ? NUM_WAY / 4 : NUM_WAY;
  way = find_way(quarter_metadata_cache[set], champsim::block_number(full_addr), min_way, max_way);
  hit = way != NUM_WAY;

  if (hit)
  {
    if (metadata_access)
    {
      quarter_set_duel_counter += prefetch_set_duel_increment;
      quarter_metadata_set_duel_counter += 1;
    }
    else 
    {
      quarter_set_duel_counter += 16;
      quarter_demand_set_duel_counter += 1;
    }
  }
  else
  {
    uint32_t victim_way = find_victim(triggering_cpu, set, quarter_metadata_cache[set], ip, type, min_way, max_way);
    bool bypassing = victim_way == NUM_WAY;
    if (!bypassing)
    {
      quarter_metadata_cache[set][victim_way].valid = true;
      quarter_metadata_cache[set][victim_way].block_num = champsim::block_number(full_addr);
    }
    way = victim_way;
  }

  if (way != NUM_WAY) set_etr(quarter_metadata_cache[set], set, way, triggering_cpu, ip, type, hit);

  // no metadata
  if (!metadata_access)
  {
    way = find_way(no_metadata_cache[set], champsim::block_number(full_addr), 0, NUM_WAY);
    hit = way != NUM_WAY;

    if (hit)
    {
      no_set_duel_counter += 16;
      no_demand_set_duel_counter += 1;
    }
    else
    {
      uint32_t victim_way = find_victim(triggering_cpu, set, no_metadata_cache[set], ip, type, 0, NUM_WAY);
      bool bypassing = victim_way == NUM_WAY;
      if (!bypassing)
      {
        no_metadata_cache[set][victim_way].valid = true;
        no_metadata_cache[set][victim_way].block_num = champsim::block_number(full_addr);
      }
      way = victim_way;
    }

    if (way != NUM_WAY) set_etr(no_metadata_cache[set], set, way, triggering_cpu, ip, type, hit);
  }

  metadata_partition_epoch += 1;
  if (metadata_partition_epoch >= METADATA_PARTITION_EPOCH_LENGTH)
  {
    if (half_set_duel_counter > quarter_set_duel_counter && half_set_duel_counter > no_set_duel_counter)
      metadata_ways = NUM_WAY / 2;
    else if (quarter_set_duel_counter > no_set_duel_counter) 
      metadata_ways = NUM_WAY / 4;
    else
      metadata_ways = 0;

    printf("Finish Partition Epoch : Half - %u (Dem: %u Met: %u) Quarter - %u (Dem: %u Met: %u) None - %u (Dem: %u Met: 0) --> METADATA_WAYS %u\n", half_set_duel_counter, half_demand_set_duel_counter, half_metadata_set_duel_counter, quarter_set_duel_counter, quarter_demand_set_duel_counter, quarter_metadata_set_duel_counter, no_set_duel_counter, no_demand_set_duel_counter, metadata_ways);
    half_set_duel_counter = 0;
    quarter_set_duel_counter = 0;
    no_set_duel_counter = 0;
    metadata_partition_epoch = 0;

    half_metadata_set_duel_counter = 0;
    quarter_metadata_set_duel_counter = 0;

    half_demand_set_duel_counter = 0;
    quarter_demand_set_duel_counter = 0;
    no_demand_set_duel_counter = 0;
  }
}

streamline::streamline(CACHE* cache) : streamline(cache, cache->NUM_SET, cache->NUM_WAY) {}

streamline::streamline(CACHE* cache, long sets, long ways) 
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
                      PREFETCH_ACCURACY_EPOCH_LENGTH(2048),
                      METADATA_PARTITION_EPOCH_LENGTH(16384)
{
  etr = std::vector<std::vector<int>>(NUM_SET, std::vector<int>(NUM_WAY));
  etr_clock = std::vector<int>(NUM_SET, GRANULARITY);
  current_timestamp = std::vector<int>(NUM_SET, 0);

  for(uint32_t set = 0; set < NUM_SET; set++)
  {
    if (is_sampled_set(set))
    {
      int modifier = 1 << LOG2_LLC_SET;
      int limit = 1 << LOG2_SAMPLED_CACHE_SETS;
      for (int i = 0; i < limit; i++)
        sampled_cache[set + modifier*i] = new SampledCacheLine[SAMPLED_CACHE_WAYS]();

      half_metadata_cache[set] = new SetDuelingCacheLine[NUM_WAY]();
      quarter_metadata_cache[set] = new SetDuelingCacheLine[NUM_WAY]();
      no_metadata_cache[set] = new SetDuelingCacheLine[NUM_WAY]();
    }
  }

  metadata_ways = NUM_WAY / 4;

  metadata_partition_epoch = 0;
  no_set_duel_counter = 0;
  quarter_set_duel_counter = 0;
  half_set_duel_counter = 0;

  half_metadata_set_duel_counter = 0;
  quarter_metadata_set_duel_counter = 0;
  half_demand_set_duel_counter = 0;
  quarter_demand_set_duel_counter = 0;
  no_demand_set_duel_counter = 0;

  prefetch_accuracy_epoch = 0;
  prefetch_useful_count = 0;
  prefetch_set_duel_increment = 4;
}

long streamline::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type)
{
  bool metadata_access = (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE);
  uint32_t min_way;
  uint32_t max_way;

  if (metadata_access)
  {
    if (metadata_ways == 0) return NUM_WAY; // Don't Allocate
    
    min_way = 0;
    max_way = metadata_ways;
  }
  else
  {
    min_way = metadata_ways;
    max_way = NUM_WAY;
  }

  for (uint32_t way = min_way; way < max_way; way++) {
    if (current_set[way].valid == false || (metadata_access != current_set[way].metadata)) {
      return way;
    }
  }

  // your eviction policy goes here
  int max_etr = 0;
  int victim_way = min_way;
  for (uint32_t way = min_way; way < max_way; way++) {
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

void streamline::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit)
{
  update_set_dueling(triggering_cpu, set, full_addr, ip, type);

  if (type == access_type::WRITE)
  {
    if(!hit) etr[set][way] = -1 * INF_ETR;
    return;
  }

  uint64_t signature = build_signature(triggering_cpu, ip, type, hit);

  if (is_sampled_set(set))
  {
    uint64_t sampled_cache_index = get_sampled_cache_index(full_addr.to<uint64_t>());
    uint64_t sampled_cache_tag = get_sampled_cache_tag(full_addr.to<uint64_t>());
    int sampled_cache_way = search_sampled_cache(sampled_cache_tag, sampled_cache_index);

    if (sampled_cache_way > -1) {
      uint64_t last_signature = sampled_cache[sampled_cache_index][sampled_cache_way].signature;
      uint64_t last_timestamp = sampled_cache[sampled_cache_index][sampled_cache_way].timestamp;
      int sample = time_elapsed(current_timestamp[set], last_timestamp);

      if (sample <= INF_RD) {
        if (type == access_type::PREFETCH) sample = sample * FLEXMIN_PENALTY;
        if (type == access_type::METADATA_STORE) sample = INF_RD; // Penalize Metadata Stores (Useless Store)

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
        sampled_cache[sampled_cache_index][w].timestamp = current_timestamp[set];
        break;
      }
    }
    
    current_timestamp[set] = increment_timestamp(current_timestamp[set]);
  }

  if(etr_clock[set] == GRANULARITY) {
      for (uint32_t w = 0; w < NUM_WAY; w++) {
          if ((uint32_t) w != way && abs(etr[set][w]) < INF_ETR) {
              etr[set][w]--;
          }
      }
      etr_clock[set] = 0;
  }
  etr_clock[set]++;
  
  
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

void streamline::replacement_update_prefetcher_stats(bool useful)
{
  if (useful)
    prefetch_useful_count += 1;

  prefetch_accuracy_epoch += 1;
  if (prefetch_accuracy_epoch >= PREFETCH_ACCURACY_EPOCH_LENGTH)
  {
    double accuracy = ((double) prefetch_useful_count) / ((double) prefetch_accuracy_epoch);

    if (accuracy < 0.1) prefetch_set_duel_increment = 1;
    else if (accuracy < 0.25) prefetch_set_duel_increment = 2;
    else if (accuracy < 0.5) prefetch_set_duel_increment = 3;
    else if (accuracy < 0.7) prefetch_set_duel_increment = 4;
    else if (accuracy < 0.9) prefetch_set_duel_increment = 6;
    else if (accuracy < 0.95) prefetch_set_duel_increment = 7;
    else prefetch_set_duel_increment = 8;

    prefetch_set_duel_increment *= 4 /*cmc_multiplier*/;

    prefetch_accuracy_epoch = 0;
    prefetch_useful_count = 0;
  }
}