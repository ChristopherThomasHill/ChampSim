#ifndef __TRIAGE_TEST_H__
#define __TRIAGE_TEST_H__

#include <cstdint>

#include "address.h"
#include "modules.h"
#include <cstdlib>
#include <fstream>
#include <utility>
#include <map>
#include <string>
#include <cstring>
#include <algorithm>
#include <vector>

uint64_t addr_hash(uint64_t key);

class Hawkeye {
    struct ADDR_INFO {
        uint64_t last_quanta;
        champsim::address PC; 

        void init() {
            last_quanta = 0;
            PC = champsim::address(0);
        }

        void update(uint64_t cur_quanta, champsim::address pc) {
            last_quanta = cur_quanta;
            PC = pc;
        }
    };

    struct OPTgen {
        std::vector<uint64_t> liveness_history;
        uint64_t CACHE_SIZE;

        void init(uint64_t size) {CACHE_SIZE = size;}

        void add_access(uint64_t cur_quanta) {
            liveness_history.resize(cur_quanta + 1);
            liveness_history.at(cur_quanta) = 0;
        }

        bool should_cache(uint64_t cur_quanta, uint64_t last_quanta) {
            bool is_cache = true;

            assert(cur_quanta <= liveness_history.size());
            uint64_t i = last_quanta;
            while (i != cur_quanta) {
                if(liveness_history.at(i) >= CACHE_SIZE) {
                    is_cache = false;
                    break;
                }
                i++;
            }

            if (is_cache) {
                i = last_quanta;
                while (i != cur_quanta) {
                    liveness_history.at(i++)++;
                }
                assert(i == cur_quanta);
            }

            return is_cache;    
        }
    };

    uint64_t num_sets, num_ways;
    std::map<champsim::address, uint8_t> hawkeye_pred = {};
    std::vector<std::vector<uint8_t>> rrpv = {};
    std::vector<std::vector<bool>> valid = {};
    uint8_t srrip_max = 3, srrip_long = 2, hawkeye_threshold = 16, hawkeye_max = 31;

    std::vector<uint64_t> optgen_timer = {};
    std::vector<OPTgen> optgen = {};
    std::map<uint64_t, std::map<champsim::block_number, ADDR_INFO>> optgen_addr_history = {};
    std::map<champsim::block_number, champsim::address> signature = {};

    void increment(champsim::address pc) {
        if(hawkeye_pred.find(pc) == hawkeye_pred.end()) {
            hawkeye_pred[pc] = hawkeye_threshold;
        } else if(hawkeye_pred[pc] < hawkeye_max) {
            hawkeye_pred[pc]++;
        }
    }

    void decrement(champsim::address pc) {
        if(hawkeye_pred.find(pc) == hawkeye_pred.end()) {
            hawkeye_pred[pc] = hawkeye_threshold;
        } else if(hawkeye_pred[pc] > 0) {
            hawkeye_pred[pc]--;
        }
    }

    bool predict(champsim::address pc) { // Predict true if miss Hawkeye predictor table
        return hawkeye_pred.find(pc) == hawkeye_pred.end() || hawkeye_pred[pc] >= hawkeye_threshold;
    }

public:
    Hawkeye(uint64_t _num_sets, uint64_t _num_ways): num_sets(_num_sets), num_ways(_num_ways) {
        rrpv.resize(num_sets);
        optgen.resize(num_sets);
        optgen_timer.resize(num_sets);
        valid.resize(num_sets);
        for(uint64_t set = 0; set < num_sets; set++) {
            rrpv[set].resize(num_ways, srrip_max);
            valid[set].resize(num_ways, false);
            optgen[set].init(num_ways > 2 ? (num_ways - 2) : 1); // -1 for bypass, another -1 was found to work well for Hawkeye
        }
    }

    uint64_t find_victim(uint64_t set, std::vector<champsim::block_number> set_data) {
        // Evict cache averse first
        for(uint64_t i = 0; i < num_ways; i++) {
            if(rrpv[set][i] == srrip_max || !valid[set][i]) {
                return i;
            }
        }

        uint64_t evict_way = num_ways;
        int8_t evict_rrpv = 0;
        for(uint64_t i = 0; i < num_ways; i++) {
            if(rrpv[set][i] >= evict_rrpv) {
                evict_rrpv = rrpv[set][i];
                evict_way = i;
            }
        }

        // Train negatively on cache-friendly eviction
        // Should technically be sampled, but simpler not to (negligible effect either way)
        decrement(signature[set_data[evict_way]]);

        return evict_way;
    }

    void update_replacement_state(champsim::address pc, uint64_t set, uint64_t way, bool hit, champsim::block_number addr) {
        if(hit) {
            return;
        }

        // Should technically be sampled, but simpler not to (negligible effect either way)
        uint64_t cur_quanta = optgen_timer[set];
        signature[addr] = pc;
        if(optgen_addr_history[set].find(addr) != optgen_addr_history[set].end()) {
            uint64_t last_quanta = optgen_addr_history[set][addr].last_quanta;
            champsim::address last_pc = optgen_addr_history[set][addr].PC;
            if(optgen[set].should_cache(cur_quanta, last_quanta)) {
                increment(last_pc);
            } else {
                decrement(last_pc);
            }
            optgen[set].add_access(cur_quanta);
        } else {
            optgen_addr_history[set][addr].init();
            optgen[set].add_access(cur_quanta);
        }
        optgen_addr_history[set][addr].update(optgen_timer[set], pc);
        optgen_timer[set]++;

        if(predict(pc)) { // Cache-friendly
            // Only age if inserting cache-friendly line
            bool saturated = false;
            for(uint64_t w = 0; w < num_ways; w++) {
                if((w != way && rrpv[set][w] >= srrip_long) && valid[set][w]) {
                    saturated = true;
                    break;
                }
            }
            if(!saturated) {
                for(uint64_t w = 0; w < num_ways; w++) {
                    if(rrpv[set][w] < srrip_long) {
                        rrpv[set][w]++;
                    }
                }
            }
            rrpv[set][way] = 0;
        } else { // Cache-averse
            rrpv[set][way] = srrip_max;
        }
        valid[set][way] = true;

    }
};

struct MetadataCache {
    struct MetadataEntry {
        champsim::block_number trigger;
        champsim::block_number pf;

        void update(champsim::block_number _trigger, champsim::block_number _pf) {trigger = _trigger; pf = _pf;}
        MetadataEntry() {update(champsim::block_number(0), champsim::block_number(0));}
    };

    CACHE* llc_cache = nullptr;
    std::vector<std::vector<MetadataEntry>> entries = {};
    uint64_t metadata_ways_per_set = 8;
    uint64_t total_metadata_ways = 2048 * metadata_ways_per_set;
    uint64_t entries_per_way = 12;
    Hawkeye hawkeye;

    MetadataCache(CACHE* _llc_cache, uint64_t _metadata_ways_per_set): llc_cache(_llc_cache), metadata_ways_per_set(_metadata_ways_per_set), total_metadata_ways(llc_cache->NUM_SET * _metadata_ways_per_set), hawkeye(total_metadata_ways, entries_per_way) {
        entries.resize(total_metadata_ways, std::vector<MetadataEntry>(entries_per_way));
    }

    uint64_t get_idx(champsim::block_number trigger, uint64_t num_ways) {
        uint64_t t = addr_hash(trigger.to<uint64_t>());
        uint64_t set = t % llc_cache->NUM_SET;
        uint64_t way = (t >> champsim::lg2(llc_cache->NUM_SET)) % metadata_ways_per_set;
        return set * num_ways + way;
    }

    // Computes index into entries std::vector
    uint64_t get_entry_idx(champsim::block_number trigger) {
        return get_idx(trigger, metadata_ways_per_set);
    }

    // Computes index into cache block std::vector
    uint64_t get_block_idx(champsim::block_number trigger) {
        return get_idx(trigger, llc_cache->NUM_WAY);
    }

    uint64_t find(champsim::block_number trigger, uint64_t idx) {
        for(uint64_t entry = 0; entry < entries_per_way; entry++) {
            if(entries.at(idx).at(entry).trigger == trigger) {
                return entry;
            }
        }
        return entries_per_way;
    }

    void insert(champsim::address pc, champsim::block_number trigger, champsim::block_number pf) {
        bool hit = true;
        auto entry_idx = get_entry_idx(trigger);
        auto entry = find(trigger, entry_idx);

        if(entry == entries_per_way) {
            hit = false;

            // Get entry to evict
            std::vector<champsim::block_number> set_data;
            std::transform(entries.at(entry_idx).begin(), entries.at(entry_idx).end(), std::back_inserter(set_data), [](const auto& x) {return x.trigger;});
            entry = hawkeye.find_victim(entry_idx, set_data);

            // Set is_metadata as needed
            auto block_idx = get_block_idx(trigger);
            llc_cache->block.at(block_idx).metadata = true;
            llc_cache->block.at(block_idx).valid = false;
            llc_cache->block.at(block_idx).address = champsim::address{0};
        }

        // Update entry with new data
        entries.at(entry_idx).at(entry).update(trigger, pf);
        hawkeye.update_replacement_state(pc, entry_idx, entry, hit, trigger);
    }

    champsim::block_number predict(champsim::block_number trigger) {
        auto entry_idx = get_entry_idx(trigger);
        auto entry = find(trigger, entry_idx);
        return entry == entries_per_way ? champsim::block_number(0) : entries.at(entry_idx).at(entry).pf;
    }

    uint64_t check_metadata_size() {
        uint64_t num_metadata_ways = 0;
        for(uint64_t set = 0; set < llc_cache->NUM_SET; set++) {
            for(uint64_t way = 0; way < llc_cache->NUM_WAY; way++) {
                if(llc_cache->block.at(set * llc_cache->NUM_WAY + way).metadata) {
                    num_metadata_ways++;
                }
            }
        }
        return num_metadata_ways;
    }
};


struct triage : public champsim::modules::prefetcher {
    using prefetcher::prefetcher;
    // Unlimited size for simplicity
    std::map<champsim::address, champsim::block_number> training_unit;
    MetadataCache* metadata_cache = nullptr;

    champsim::block_number predict(champsim::block_number block_addr);
    void prefetcher_initialize();
    uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address pc, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in);
    uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
};


#endif
