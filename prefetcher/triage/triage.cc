#include "cache.h"

#include "triage.h"
#include <iostream>

#define MAX_DEGREE 4

uint64_t addr_hash(uint64_t key) {
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    key = key + (key << 31);
    return key;
}

void triage::prefetcher_initialize() {
    metadata_cache = new MetadataCache(this->intern_, 8);
}

champsim::block_number triage::predict(champsim::block_number block_addr) {
    return metadata_cache->predict(block_addr);
}

uint64_t ii = 0;

uint32_t triage::prefetcher_cache_operate(champsim::address addr, champsim::address pc, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in) {
    champsim::block_number block_addr(addr);
    if(type != access_type::LOAD || block_addr == champsim::block_number(0)) {
        return metadata_in;
    }

    if(ii++ % (1000 * 1000) == 0) {
        double num_metadata_ways = double(metadata_cache->check_metadata_size());
        double cache_size = intern_->NUM_SET * intern_->NUM_WAY;
        std::cout << "Current Metadata Allocation = " << num_metadata_ways << " (" << num_metadata_ways / cache_size << ")" << std::endl;
    }

    champsim::block_number pred = predict(block_addr);
    for(uint64_t i = 0; i < MAX_DEGREE && pred != champsim::block_number(0); i++) {
        prefetch_line(champsim::address(pred), true, 0);
        pred = predict(pred);
    }

    // Triage doesn't insert on cache hits
    if(training_unit.find(pc) != training_unit.end() && !cache_hit) {
        metadata_cache->insert(pc, training_unit[pc], block_addr);
    }
    training_unit[pc] = block_addr;

    return metadata_in;
}

uint32_t triage::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in) {
    return metadata_in;
}
