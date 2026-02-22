#include "cache.h"

#include "triangel.h"
#include <iostream>

uint64_t addr_hash_triangel(uint64_t key) {
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    key = key + (key << 31);
    return key;
}

void triangel::prefetcher_initialize() {
    uint64_t metadata_associativity = 8;
    metadata_cache = new MetadataCacheTriangel(this->intern_, metadata_associativity);
    mrb = new MetadataReuseBuffer();
    training_unit = new TrainingUnit();
    triangel = new Triangel(training_unit, metadata_associativity);
    std::cout << "Triangel" << std::endl;
}

champsim::block_number triangel::predict(champsim::block_number block_addr) {
    uint64_t mrb_pf = mrb->check(block_addr.to<uint64_t>());
    if(mrb_pf != 0) {
        return champsim::block_number(mrb_pf);
    }
    auto mc_pf = metadata_cache->predict(block_addr);
    if(mc_pf != champsim::block_number(0)) {
        mrb->insert(block_addr.to<uint64_t>(), mc_pf.to<uint64_t>());
    }
    return mc_pf;
}

uint32_t triangel::prefetcher_cache_operate(champsim::address addr, champsim::address pc, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in) {
    champsim::block_number block_addr(addr);
    if(type != access_type::LOAD || block_addr == champsim::block_number(0)) {
        return metadata_in;
    }

    if(ii++ % (1000 * 1000) == 0) {
        double num_metadata_ways = double(metadata_cache->check_metadata_size());
        double cache_size = intern_->NUM_SET * intern_->NUM_WAY;
        std::cout << "Current Metadata Allocation = " << num_metadata_ways << " (" << num_metadata_ways / cache_size << ")" << std::endl;
        // triangel->print();
    }

    TrainingUnitEntry* tu_entry = training_unit->find_entry(pc.to<uint64_t>(), true);

    bool should_pf = false;
    uint64_t cur_degree = triangel->get_degree(tu_entry, block_addr.to<uint64_t>(), should_pf, this->intern_->in_cache(addr, false /*metadata*/), this->intern_->was_prefetched(addr, false /*metadata*/));

    champsim::block_number pred = predict(block_addr);
    for(uint64_t i = 0; i < cur_degree && pred != champsim::block_number(0); i++) {
        prefetch_line(champsim::address(pred), true, 0, pc);
        pred = predict(pred);
    }

    if(tu_entry->valid() && should_pf) {
        metadata_cache->insert(pc, champsim::block_number(tu_entry->get_training_addr()), block_addr);
    }

    if(tu_entry->is_new_addr(block_addr.to<uint64_t>())) {
        tu_entry->add_access(block_addr.to<uint64_t>());
    }

    return metadata_in;
}

uint32_t triangel::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in) {
    return metadata_in;
}
