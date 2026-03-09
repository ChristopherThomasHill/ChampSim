#include <cmath>
#include <iostream>

#include "champsim.h"
#include "mockingjay_half_metadata.h"

bool mockingjay_half_metadata::is_sampled_set(long set)
{
  long mask_length = LOG2_LLC_SET - LOG2_SAMPLED_SETS;
  long mask = (1 << mask_length) - 1;
  return (set & mask) == ((set >> (LOG2_LLC_SET - mask_length)) & mask);
}

uint64_t mockingjay_half_metadata::CRC_HASH(uint64_t _blockAddress)
{
  static const unsigned long long crcPolynomial = 3988292384ULL;
  unsigned long long _returnVal = _blockAddress;
  for( unsigned int i = 0; i < 3; i++)
      _returnVal = ( ( _returnVal & 1 ) == 1 ) ? ( ( _returnVal >> 1 ) ^ crcPolynomial ) : ( _returnVal >> 1 );
  return _returnVal;
}

uint64_t mockingjay_half_metadata::build_signature(uint32_t triggering_cpu, champsim::address ip, access_type type, uint8_t hit)
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

uint64_t mockingjay_half_metadata::get_sampled_cache_index(uint64_t full_addr)
{
  full_addr = full_addr >> LOG2_BLOCK_SIZE;
  full_addr = (full_addr << (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET))) >> (64 - (LOG2_SAMPLED_CACHE_SETS + LOG2_LLC_SET));
  return full_addr;
}

uint64_t mockingjay_half_metadata::get_sampled_cache_tag(uint64_t x)
{
  x >>= LOG2_LLC_SET + LOG2_BLOCK_SIZE + LOG2_SAMPLED_CACHE_SETS;
  x = (x << (64 - SAMPLED_CACHE_TAG_BITS)) >> (64 - SAMPLED_CACHE_TAG_BITS);
  return x;
}

int mockingjay_half_metadata::search_sampled_cache(uint64_t blockAddress, bool metadata, uint32_t set)
{
  SampledCacheLine* sampled_set = metadata ? metadata_sampled_cache[set] : sampled_cache[set];
  for (int way = 0; way < SAMPLED_CACHE_WAYS; way++) {
      if (sampled_set[way].valid && (sampled_set[way].tag == blockAddress)) {
          return way;
      }
  }
  return -1;
}

void mockingjay_half_metadata::detrain(uint32_t set, int way, bool metadata)
{
  SampledCacheLine temp = metadata ? metadata_sampled_cache[set][way] : sampled_cache[set][way];
  if (!temp.valid) {
      return;
  }

  if (rdp.count(temp.signature)) {
      rdp[temp.signature] = std::min(rdp[temp.signature] + 1, INF_RD);
      sampled_table[{temp.ip, temp.type}][INF_RD] += 1;
  } else {
      rdp[temp.signature] = INF_RD;
      sampled_table[{temp.ip, temp.type}][INF_RD] += 1;
  }

  if (metadata) metadata_sampled_cache[set][way].valid = false;
  else sampled_cache[set][way].valid = false;
}

int mockingjay_half_metadata::temporal_difference(int init, int sample)
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

int mockingjay_half_metadata::increment_timestamp(int input)
{
  input++;
  input = input % (1 << TIMESTAMP_BITS);
  return input;
}

int mockingjay_half_metadata::time_elapsed(int global, int local)
{
   if (global >= local) {
      return global - local;
    }
    global = global + (1 << TIMESTAMP_BITS);
    return global - local;
}

mockingjay_half_metadata::mockingjay_half_metadata(CACHE* cache) : mockingjay_half_metadata(cache, cache->NUM_SET, cache->NUM_WAY) {}

mockingjay_half_metadata::mockingjay_half_metadata(CACHE* cache, long sets, long ways) 
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
                      FLEXMIN_PENALTY(2.0 - std::log2(NUM_CPUS)/4.0)
{
  etr = std::vector<std::vector<int>>(NUM_SET, std::vector<int>(NUM_WAY));
  etr_clock = std::vector<int>(NUM_SET, GRANULARITY);
  metadata_etr_clock = std::vector<int>(NUM_SET, GRANULARITY);
  current_timestamp = std::vector<int>(NUM_SET, 0);
  metadata_current_timestamp = std::vector<int>(NUM_SET, 0);

  for(uint32_t set = 0; set < NUM_SET; set++)
  {
    if (is_sampled_set(set)) {
      int modifier = 1 << LOG2_LLC_SET;
      int limit = 1 << LOG2_SAMPLED_CACHE_SETS;
      for (int i = 0; i < limit; i++)
      {
        sampled_cache[set + modifier*i] = new SampledCacheLine[SAMPLED_CACHE_WAYS]();
        metadata_sampled_cache[set + modifier*i] = new SampledCacheLine[SAMPLED_CACHE_WAYS]();
      }
    }
  }

  set_age = std::vector<uint64_t>(NUM_SET, 0);
}

long mockingjay_half_metadata::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type)
{
  uint32_t min_way;
  uint32_t max_way;

  if (type == access_type::METADATA_LOAD || type == access_type::METADATA_STORE)
  {
    min_way = 0;
    max_way = NUM_WAY / 2;
  }
  else
  {
    min_way = NUM_WAY / 2;
    max_way = NUM_WAY;
  }

  for (uint32_t way = min_way; way < max_way; way++) {
    if (current_set[way].valid == false) {
      return way;
    }
  }

  // your eviction policy goes here
  int max_etr = 0;
  int victim_way = 0;
  for (uint32_t way = min_way; way < max_way; way++) {
    if (abs(etr[set][way]) > max_etr ||
          (abs(etr[set][way]) == max_etr &&
            etr[set][way] < 0)) { //TECHNICALLY this logic is not correct. While this does prioritize negative values, it does prioritize negative values over other negative values.
      max_etr = abs(etr[set][way]);
      victim_way = way;
    }
  }
  
  uint64_t pc_signature = build_signature(triggering_cpu, ip, type, false);
  if (access_type{type} != access_type::WRITE && rdp.count(pc_signature) &&
          (rdp[pc_signature] > MAX_RD || rdp[pc_signature] / GRANULARITY > max_etr)) {
      return NUM_WAY;
  }
  
  return victim_way;
}

void mockingjay_half_metadata::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, bool hit, bool useful)
{
  track_info(set, champsim::block_number(full_addr), ip, type);

  if (type == access_type::WRITE)
  {
    if(!hit) etr[set][way] = -1 * INF_ETR;
    return;
  }

  if (type == access_type::METADATA_LOAD && !hit)
  {
    return; // Load misses are kind of useless in behavior
  }
  
  uint64_t signature = build_signature(triggering_cpu, ip, type, hit);
  bool metadata_access = (type == access_type::METADATA_STORE || type == access_type::METADATA_LOAD);

  if (is_sampled_set(set))
  {
    uint64_t sampled_cache_index = get_sampled_cache_index(full_addr.to<uint64_t>());
    uint64_t sampled_cache_tag = get_sampled_cache_tag(full_addr.to<uint64_t>());
    int sampled_cache_way = search_sampled_cache(sampled_cache_tag, metadata_access, sampled_cache_index);

    if (sampled_cache_way > -1) {
      uint64_t last_signature = metadata_access ? metadata_sampled_cache[sampled_cache_index][sampled_cache_way].signature : sampled_cache[sampled_cache_index][sampled_cache_way].signature;
      uint64_t last_timestamp = metadata_access ? metadata_sampled_cache[sampled_cache_index][sampled_cache_way].timestamp : sampled_cache[sampled_cache_index][sampled_cache_way].timestamp;
      champsim::address last_ip = metadata_access ? metadata_sampled_cache[sampled_cache_index][sampled_cache_way].ip : sampled_cache[sampled_cache_index][sampled_cache_way].ip;
      access_type last_type = metadata_access ? metadata_sampled_cache[sampled_cache_index][sampled_cache_way].type : sampled_cache[sampled_cache_index][sampled_cache_way].type;
      
      int sample = time_elapsed(metadata_access ? metadata_current_timestamp[set] : current_timestamp[set], last_timestamp);

      if (sample <= INF_RD) {
        if (type == access_type::PREFETCH) sample = sample * FLEXMIN_PENALTY;
        else if (type == access_type::METADATA_STORE) sample = 2 * INF_RD; // Penalize Metadata Stores (Useless Store)
        
        if (rdp.count(last_signature)) {
          int init = rdp[last_signature];
          rdp[last_signature] = temporal_difference(init, sample);
          sampled_table[{last_ip, last_type}][sample] += 1;
        } else {
          rdp[last_signature] = sample;
          sampled_table[{last_ip, last_type}][sample] += 1;
        }

        if (metadata_access) metadata_sampled_cache[sampled_cache_index][sampled_cache_way].valid = false;
        else sampled_cache[sampled_cache_index][sampled_cache_way].valid = false;
      }
    }


    int lru_way = -1;
    int lru_rd = -1;
    for (int w = 0; w < SAMPLED_CACHE_WAYS; w++) {
      if (metadata_access ? metadata_sampled_cache[sampled_cache_index][w].valid == false : sampled_cache[sampled_cache_index][w].valid == false) {
        lru_way = w;
        lru_rd = INF_RD + 1;
        continue;
      }

      uint64_t last_timestamp = metadata_access ? metadata_sampled_cache[sampled_cache_index][w].timestamp : sampled_cache[sampled_cache_index][w].timestamp;
      int sample = time_elapsed(metadata_access ? metadata_current_timestamp[set] : current_timestamp[set], last_timestamp);
      if (sample > INF_RD) {
        lru_way = w;
        lru_rd = INF_RD + 1;
        detrain(sampled_cache_index, w, metadata_access);
      } else if (sample > lru_rd) {
        lru_way = w;
        lru_rd = sample;
      }
    }
    detrain(sampled_cache_index, lru_way, metadata_access);

    for (int w = 0; w < SAMPLED_CACHE_WAYS; w++) {
      if (metadata_access)
      {
        if (metadata_sampled_cache[sampled_cache_index][w].valid == false) {
          metadata_sampled_cache[sampled_cache_index][w].valid = true;
          metadata_sampled_cache[sampled_cache_index][w].signature = signature;
          metadata_sampled_cache[sampled_cache_index][w].tag = sampled_cache_tag;
          metadata_sampled_cache[sampled_cache_index][w].timestamp = metadata_current_timestamp[set];

          metadata_sampled_cache[sampled_cache_index][w].ip = ip;
          metadata_sampled_cache[sampled_cache_index][w].type = type;
          break;
        }
      }
      else
      {
        if (sampled_cache[sampled_cache_index][w].valid == false) {
          sampled_cache[sampled_cache_index][w].valid = true;
          sampled_cache[sampled_cache_index][w].signature = signature;
          sampled_cache[sampled_cache_index][w].tag = sampled_cache_tag;
          sampled_cache[sampled_cache_index][w].timestamp = current_timestamp[set];

          sampled_cache[sampled_cache_index][w].ip = ip;
          sampled_cache[sampled_cache_index][w].type = type;
          break;
        }
      }
    }
    
    if (metadata_access)
    {
      metadata_current_timestamp[set] = increment_timestamp(metadata_current_timestamp[set]);
    }
    else
    {
      current_timestamp[set] = increment_timestamp(current_timestamp[set]);
    }
  }

  if (metadata_access)
  {
    if(metadata_etr_clock[set] == GRANULARITY) {
        for (uint32_t w = 0; w < NUM_WAY / 2; w++) {
            if ((uint32_t) w != way && abs(etr[set][w]) < INF_ETR) {
                etr[set][w]--;
            }
        }
        metadata_etr_clock[set] = 0;
    }
    metadata_etr_clock[set]++;
  }
  else
  {
    if(etr_clock[set] == GRANULARITY) {
        for (uint32_t w = NUM_WAY / 2; w < NUM_WAY; w++) {
            if ((uint32_t) w != way && abs(etr[set][w]) < INF_ETR) {
                etr[set][w]--;
            }
        }
        etr_clock[set] = 0;
    }
    etr_clock[set]++;
  }
  
  if (way < NUM_WAY) {
    assert(hit || type != access_type::METADATA_LOAD);
    if(!rdp.count(signature)) {
      if (NUM_CPUS == 1) {
        etr[set][way] = 0;
        prediction_table[{ip, type}][0] += 1;
      } else {
        etr[set][way] = INF_ETR;
        prediction_table[{ip, type}][INF_ETR] += 1;
      }
    } else {
      if(rdp[signature] > MAX_RD) {
        etr[set][way] = INF_ETR;
        prediction_table[{ip, type}][INF_ETR] += 1;
      } else {
        etr[set][way] = rdp[signature] / GRANULARITY;
        prediction_table[{ip, type}][rdp[signature] / GRANULARITY] += 1;
      }
    }
  }
}

void mockingjay_half_metadata::track_info(long set, champsim::block_number block_addr, champsim::address ip, access_type type)
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
  if (!metadata) set_age[set]++;
}

void mockingjay_half_metadata::replacement_final_stats()
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

   // ---------------------------------------------------------
  // 6. Print sampled_table (raw values, no bins)
  // ---------------------------------------------------------
  {
    const uint64_t MAX_VALUE = 2 * INF_RD; // metadata store can force sample = 2*INF_RD

    struct SortableSigHist {
      const Signature* sig_ptr;
      const std::unordered_map<uint64_t, uint64_t>* hist_ptr;
      uint64_t total_count;
    };

    std::vector<SortableSigHist> sorted_sampled_list;

    for (const auto& entry : sampled_table) {
      const Signature& sig = entry.first;
      const auto& hist = entry.second;

      uint64_t total = 0;
      for (const auto& [value, count] : hist)
        total += count;

      if (total >= 30) {
        sorted_sampled_list.push_back({&sig, &hist, total});
      }
    }

    std::sort(sorted_sampled_list.begin(), sorted_sampled_list.end(),
      [](const SortableSigHist& a, const SortableSigHist& b) {
        return a.total_count > b.total_count;
      });

    std::cout << "\nSampledTable_PC,AccessType,TotalCount";
    for (uint64_t i = 0; i <= MAX_VALUE; ++i) {
      std::cout << ",Sample_" << i;
    }
    std::cout << "\n";

    for (const auto& item : sorted_sampled_list) {
      const Signature& sig = *item.sig_ptr;
      const auto& hist = *item.hist_ptr;

      std::cout << "0x" << std::hex << sig.pc.to<uint64_t>() << std::dec
                << "," << access_type_names[static_cast<int>(sig.type)]
                << "," << item.total_count;

      for (uint64_t i = 0; i <= MAX_VALUE; ++i) {
        auto it = hist.find(i);
        if (it != hist.end())
          std::cout << "," << it->second;
        else
          std::cout << ",0";
      }

      std::cout << "\n";
    }
  }

  // ---------------------------------------------------------
  // 7. Print prediction_table (raw values, no bins)
  // ---------------------------------------------------------
  {
    const uint64_t MAX_VALUE = INF_ETR;

    struct SortableSigHist {
      const Signature* sig_ptr;
      const std::unordered_map<uint64_t, uint64_t>* hist_ptr;
      uint64_t total_count;
    };

    std::vector<SortableSigHist> sorted_prediction_list;

    for (const auto& entry : prediction_table) {
      const Signature& sig = entry.first;
      const auto& hist = entry.second;

      uint64_t total = 0;
      for (const auto& [value, count] : hist)
        total += count;

      if (total >= 30) {
        sorted_prediction_list.push_back({&sig, &hist, total});
      }
    }

    std::sort(sorted_prediction_list.begin(), sorted_prediction_list.end(),
      [](const SortableSigHist& a, const SortableSigHist& b) {
        return a.total_count > b.total_count;
      });

    std::cout << "\nPredictionTable_PC,AccessType,TotalCount";
    for (uint64_t i = 0; i <= MAX_VALUE; ++i) {
      std::cout << ",Pred_" << i;
    }
    std::cout << "\n";

    for (const auto& item : sorted_prediction_list) {
      const Signature& sig = *item.sig_ptr;
      const auto& hist = *item.hist_ptr;

      std::cout << "0x" << std::hex << sig.pc.to<uint64_t>() << std::dec
                << "," << access_type_names[static_cast<int>(sig.type)]
                << "," << item.total_count;

      for (uint64_t i = 0; i <= MAX_VALUE; ++i) {
        auto it = hist.find(i);
        if (it != hist.end())
          std::cout << "," << it->second;
        else
          std::cout << ",0";
      }

      std::cout << "\n";
    }
  }
}
