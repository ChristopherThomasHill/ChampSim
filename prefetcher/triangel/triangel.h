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

uint64_t addr_hash_triangel(uint64_t key);

/*! \class small_prng
\brief From http://burtleburtle.net/bob/rand/smallprng.html
*/
class small_prng {
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;

    static inline uint32_t rot(uint32_t x, uint32_t k) noexcept { return (((x) << (k)) | ((x) >> (32 - (k)))); }
public:
    explicit small_prng(uint32_t seed = 0xdeadbeef) noexcept {
        a = 0xf1ea5eed;
        b = c = d = seed;
        for(size_t i = 0; i < 20; ++i)
            (*this)();
    }

    inline uint32_t operator()() noexcept {
        uint32_t e = a - rot(b, 27);
        a = b ^ rot(c, 17);
        b = c + d;
        c = d + e;
        d = e + a;
        return d;
    }

    uint64_t random() {
        uint64_t upper_32 = (*this)();
        uint64_t lower_32 = (*this)();
        return (upper_32 << 32) | lower_32;
    }

    uint64_t random(uint64_t exclusive_max) {
        return (((double)random()) / std::numeric_limits<uint64_t>::max()) * exclusive_max;
    }
};

struct SatCounter {
private:
    int cur_val = 0;
    int max_val = 0;

    void clamp() {
        if(cur_val < 0) {
            cur_val = 0;
        }
        if(cur_val > max_val) {
            cur_val = max_val;
        }
    }

public:
    SatCounter(uint64_t num_bits, uint64_t init_val): cur_val(init_val), max_val((1 << num_bits) - 1) {}
    int value() {return cur_val;}
    SatCounter& operator++() {
        cur_val++;
        clamp();
        return *this;
    }
    SatCounter operator++(int n) {
        SatCounter temp = *this;
        if(n != 0) {
            cur_val += n;
        } else {
            cur_val++;
        }
        clamp();
        return temp;
    }
    SatCounter& operator--() {
        cur_val--;
        clamp();
        return *this;
    }
    SatCounter operator--(int n) {
        SatCounter temp = *this;
        if(n != 0) {
            cur_val -= n;
        } else {
            cur_val--;
        }
        clamp();
        return temp;
    }
    SatCounter& operator+=(int n) {
        cur_val += n;
        clamp();
        return *this;
    }
    SatCounter operator+(int n) {
        SatCounter temp = *this;
        temp += n;
        return temp;
    }
};

struct TrainingUnitEntry {
    uint64_t pc = 0;
    std::deque<uint64_t> history = {};

    // Triangel
    SatCounter reuse_conf{4, 8};
    SatCounter pattern_conf{4, 8};
    SatCounter high_pattern_conf{4, 8};
    SatCounter replace_rate{4, 8};
    bool lookahead_two = false;
    uint64_t local_timestamp = 0;

    uint64_t hs_entries = 0;
    uint64_t hs_entries_evicted = 0;
    uint64_t scs_entries = 0;
    uint64_t scs_entries_evicted = 0;

    uint64_t pattern_scs_young_inc = 0;
    uint64_t pattern_scs_old_dec = 0;
    uint64_t pattern_hs_hit_inc = 0;
    uint64_t pattern_scs_evict_dec = 0;

    uint64_t reuse_hit_young_inc = 0;
    uint64_t reuse_hit_old_dec = 0;
    uint64_t reuse_hs_evict_dec = 0;

    uint64_t replace_evict_old_inc = 0;
    uint64_t replace_evict_young_dec = 0;

    uint64_t issued_pfs = 0;

    TrainingUnitEntry(uint64_t _pc): pc(_pc) {}

    void add_access(uint64_t cl_addr) {
        history.push_back(cl_addr);

        if((lookahead_two && history.size() > 2) || (!lookahead_two && history.size() > 1)) {
            history.pop_front();
        }

        local_timestamp++;
    }

    uint64_t get_last_addr() {
        if(history.size() > 0) {
            return history.back();
        }
        return 0;
    }

    bool is_new_addr(uint64_t addr) {
        return find(history.begin(), history.end(), addr) == history.end();
    }

    uint64_t get_training_addr() {
        if(lookahead_two) {
            if(history.size() > 1) {
                return history.front();
            }
            return 0;
        } else {
            return get_last_addr();
        }
    }

    bool valid() {
        if(lookahead_two) {
            return history.size() > 1;
        }
        return history.size() > 0;
    }
};

struct TrainingUnit {
    std::map<uint64_t, TrainingUnitEntry*> entries = {};

    TrainingUnitEntry* find_entry(uint64_t pc, bool allocate) {
        if(entries.find(pc) == entries.end()) {
            if(allocate) {
                entries[pc] = new TrainingUnitEntry(pc);
                return entries.at(pc);
            }
            return nullptr;
        }
        return entries.at(pc);
    }

    void print_triangel() {
        printf("|                                                            |Pattern Conf           |Reuse Conf       |ReplaceRate|\n");
        printf("|    IP|HC|PC|RC|RR|# ACCESS|   # PFS| HSEv  HEEn| SCEv  SCEn| SCYI  SCOD  HSHI  SCED|  HYI   HOD  HSED| EvOI  EvYD|\n");
        for(auto entry : entries) {
            if(entry.second->local_timestamp > 1000) {
                printf("|%6lx|%2u|%2u|%2u|%2u|%8lu|%8lu|%5lu %5lu|%5lu %5lu|%5lu %5lu %5lu %5lu|%5lu %5lu %5lu|%5lu %5lu|\n",
                        entry.first, entry.second->high_pattern_conf.value(), entry.second->pattern_conf.value(), entry.second->reuse_conf.value(), entry.second->replace_rate.value(), entry.second->local_timestamp, entry.second->issued_pfs,
                        entry.second->hs_entries_evicted, entry.second->hs_entries,
                        entry.second->scs_entries_evicted, entry.second->scs_entries,
                        entry.second->pattern_scs_young_inc, entry.second->pattern_scs_old_dec, entry.second->pattern_hs_hit_inc, entry.second->pattern_scs_evict_dec,
                        entry.second->reuse_hit_young_inc, entry.second->reuse_hit_old_dec, entry.second->reuse_hs_evict_dec,
                        entry.second->replace_evict_old_inc, entry.second->replace_evict_young_dec
                );
            }
        }
    }
};

class MetadataReuseBuffer {
private:
    struct MRBEntry {
        uint64_t trigger = 0;
        uint64_t pf = 0;
        uint64_t fifo = 0;
    };
    uint64_t global_timestamp = 1;
    std::vector<std::vector<MRBEntry>> mrb_cache{128, std::vector<MRBEntry>{2}};

    uint64_t get_set(uint64_t trigger) {
        return addr_hash_triangel(trigger) % mrb_cache.size();
    }
public:
    void insert(uint64_t trigger, uint64_t pf) {
        if(check(trigger) != 0) {
            return;
        }
        uint64_t set = get_set(trigger);
        uint64_t min_fifo = std::numeric_limits<uint64_t>::max();
        uint64_t evict_way = mrb_cache.at(set).size();
        for(uint64_t way = 0; way < mrb_cache.at(set).size(); way++) {
            if(mrb_cache.at(set).at(way).fifo < min_fifo) {
                min_fifo = mrb_cache.at(set).at(way).fifo;
                evict_way = way;
            }
        }
        assert(evict_way != mrb_cache.at(set).size());
        mrb_cache.at(set).at(evict_way).trigger = trigger;
        mrb_cache.at(set).at(evict_way).pf = pf;
        mrb_cache.at(set).at(evict_way).fifo = global_timestamp++;
    }

    uint64_t check(uint64_t trigger) {
        uint64_t set = get_set(trigger);
        for(uint64_t way = 0; way < mrb_cache.at(set).size(); way++) {
            if(mrb_cache.at(set).at(way).trigger == trigger) {
                return mrb_cache.at(set).at(way).pf;
            }
        }
        return 0;
    }
};

class Triangel {
private:
    TrainingUnit* training_unit = nullptr;
    bool lookahead_enabled = true;
    bool perf_bias = false; // TODO: Toggle with NUM_CPUS probably
    int max_size = 2048 * 8 * 12;

    SatCounter global_reuse_conf{7, 64};
    SatCounter global_pattern_conf{7, 64};
    SatCounter global_high_pattern_conf{7, 64};
    const int super_history = 14;

    small_prng rng{0};

    uint64_t global_timestamp = 0;
    uint64_t second_chance_timestamp = 0;

    struct TaggedLRUEntry {
        inline static uint64_t global_timestamp = 0;
        inline static uint64_t victims = 0;
        inline static uint64_t self_victims = 0;
        uint64_t tag = 0;
        uint64_t timestamp = std::numeric_limits<uint64_t>::max();

        void update(uint64_t new_tag) {
            tag = new_tag;
            timestamp = global_timestamp++;
        }
    };

    struct HistorySamplerEntry : public TaggedLRUEntry {
        uint64_t pc = 0;
        bool reused = false;
        uint64_t local_timestamp = 0;
        uint64_t next = 0;
    };

    struct SecondChanceSamplerEntry : public TaggedLRUEntry {
        uint64_t pc = 0;
        uint64_t global_timestamp = 0;
        bool used = false;
    };

    std::vector<std::vector<HistorySamplerEntry>> history_sampler{256, std::vector<HistorySamplerEntry>{2}}; // LRU
    std::vector<std::vector<SecondChanceSamplerEntry>> second_chance_sampler{32, std::vector<SecondChanceSamplerEntry>{2}}; // FIFO
public:

    Triangel(TrainingUnit* _training_unit, uint64_t ways_per_set): training_unit(_training_unit), max_size(2048 * ways_per_set * 12) {}

    bool random_chance(int reuse_conf, int replace_rate) {
        replace_rate -= 8;
        uint32_t hs_entries = history_sampler.size() * history_sampler.at(0).size();
        uint32_t base_chance = 1000000000ul / max_size * hs_entries;
        if(replace_rate > 0) {
            base_chance = base_chance << replace_rate;
        } else {
            base_chance = base_chance >> (-replace_rate);
        }
        if(reuse_conf < 3) {
            base_chance = base_chance / 16;
        }

        // return base_chance >= dist(rng);
        return base_chance >= rng.random(1000000000ul + 1);
    }

    uint64_t get_degree(TrainingUnitEntry* tu_entry, uint64_t cl_addr, bool& should_pf, bool in_cache, bool was_prefetched) {
        second_chance_timestamp++;
        const int upper_history = global_pattern_conf.value() > 64 ? 7 : 8;
        const int high_upper_history = global_high_pattern_conf.value() > 64 ? 7 : 8;
        const int upper_reuse = global_reuse_conf.value() > 64 ? 7 : 8;

        if(tu_entry->valid()) {
            if(tu_entry->get_last_addr() != cl_addr) {
                if(lookahead_enabled && tu_entry->high_pattern_conf.value() >= super_history) {
                    tu_entry->lookahead_two = true;
                }
                if(lookahead_enabled && tu_entry->pattern_conf.value() < upper_history) {
                    tu_entry->lookahead_two = false;
                }

                should_pf = tu_entry->reuse_conf.value() > upper_reuse && tu_entry->pattern_conf.value() > upper_history;

                global_timestamp++;

                update_samplers(tu_entry, cl_addr, in_cache, was_prefetched);
            }
        } else if(random_chance(8, 8) || (global_reuse_conf.value() > 64 && global_pattern_conf.value() > 64 && global_high_pattern_conf.value() > 64)) {
            // TODO: Evict + Replace tu_entry here
            if(lookahead_enabled && global_pattern_conf.value() > 96) {
                tu_entry->lookahead_two = true;
            }
        }

        if(should_pf) {
            tu_entry->issued_pfs++;
            if(tu_entry->high_pattern_conf.value() > high_upper_history) {
                return 4;
            }
            return 1;
        }
        return 0;
    }

    template<typename T>
    T* find_entry(std::vector<std::vector<T>>& cache, uint64_t cl_addr) {
        uint64_t set = addr_hash_triangel(cl_addr) % cache.size();
        for(uint64_t i = 0; i < cache.at(set).size(); i++) {
            if(cache.at(set).at(i).tag == cl_addr) {
                return &cache.at(set).at(i);
            }
        }
        return nullptr;
    }

    template<typename T>
    T* find_victim(std::vector<std::vector<T>>& cache, uint64_t cl_addr) {
        T::victims++;
        uint64_t set = addr_hash_triangel(cl_addr) % cache.size();
        uint64_t evict_way = cache.at(set).size();
        uint64_t min_timestamp = 0;
        for(uint64_t i = 0; i < cache.at(set).size(); i++) {
            if(cache.at(set).at(i).timestamp >= min_timestamp) {
                min_timestamp = cache.at(set).at(i).timestamp;
                evict_way = i;
            } else if(cache.at(set).at(i).tag == cl_addr) {
                evict_way = i;
                T::self_victims++;
                break;
            }
        }
        assert(evict_way != cache.at(set).size());
        return &cache.at(set).at(evict_way);
    }

    void update_pattern_conf(TrainingUnitEntry* tu_entry, bool increment) {
        int pattern_update = increment ? 1 : (perf_bias ? -1 : -2);
        tu_entry->pattern_conf += pattern_update;
        global_pattern_conf += pattern_update;

        int high_pattern_update = increment ? 1 : (perf_bias ? -2 : -5);
        tu_entry->high_pattern_conf += high_pattern_update;
        global_high_pattern_conf += high_pattern_update;
    }

    void update_reuse_conf(TrainingUnitEntry* tu_entry, bool increment) {
        int update = increment ? 1 : -1;
        tu_entry->reuse_conf += update;
        global_reuse_conf += update;
    }

    void update_samplers(TrainingUnitEntry* tu_entry, uint64_t cl_addr, bool in_cache, bool was_prefetched) {
        // Check SCS
        // Don't need to "disable" this with check since it would always be nullptr
        SecondChanceSamplerEntry* scs_entry = find_entry<SecondChanceSamplerEntry>(second_chance_sampler, cl_addr);
        if(scs_entry != nullptr && !scs_entry->used) {
            scs_entry->used = true;
            TrainingUnitEntry* scs_tu_entry = training_unit->find_entry(scs_entry->pc, false);
            if(scs_tu_entry != nullptr) {
                if(scs_entry->global_timestamp + 512 > second_chance_timestamp) {
                    if(scs_entry->pc == tu_entry->pc) {
                        update_pattern_conf(scs_tu_entry, true);
                        scs_tu_entry->pattern_scs_young_inc++;
                    }
                } else {
                    update_pattern_conf(scs_tu_entry, false);
                    scs_tu_entry->pattern_scs_old_dec++;
                }
            }
        }

        // Check HS
        HistorySamplerEntry* hs_entry = find_entry<HistorySamplerEntry>(history_sampler, tu_entry->get_last_addr());
        if(hs_entry != nullptr && hs_entry->pc == tu_entry->pc) {
            TrainingUnitEntry* hs_tu_entry = training_unit->find_entry(hs_entry->pc, false);
            int64_t distance = hs_tu_entry->local_timestamp - hs_entry->local_timestamp;
            if(distance > 0 && distance < max_size) {
                update_reuse_conf(tu_entry, true);
                tu_entry->reuse_hit_young_inc++;
            } else if(!hs_entry->reused) {
                update_reuse_conf(tu_entry, false);
                tu_entry->reuse_hit_old_dec++;
            }
            hs_entry->reused = true;

            if(cl_addr == hs_entry->next || (in_cache && !was_prefetched)) {
                if(cl_addr == hs_entry->next) {
                    update_pattern_conf(tu_entry, true);
                    tu_entry->pattern_hs_hit_inc++;
                }
            } else {
                // SecondChanceSamplerEntry* victim_scs_entry = find_victim<SecondChanceSamplerEntry>(second_chance_sampler, cl_addr); // TODO: How do we know it's not already in the SCS?
                SecondChanceSamplerEntry* victim_scs_entry = find_victim<SecondChanceSamplerEntry>(second_chance_sampler, hs_entry->next); // TODO: How do we know it's not already in the SCS?
                if(victim_scs_entry->pc != 0 && !victim_scs_entry->used) {
                    TrainingUnitEntry* victim_scs_tu_entry = training_unit->find_entry(victim_scs_entry->pc, false);
                    if(victim_scs_tu_entry != nullptr) {
                        update_pattern_conf(victim_scs_tu_entry, false);
                        victim_scs_tu_entry->scs_entries_evicted++;
                        victim_scs_tu_entry->pattern_scs_evict_dec++;
                    }
                }

                // Insert SCS Entry
                victim_scs_entry->pc = tu_entry->pc;
                victim_scs_entry->used = false;
                victim_scs_entry->global_timestamp = second_chance_timestamp;
                victim_scs_entry->update(hs_entry->next);
                tu_entry->scs_entries++;
            }

            assert(hs_tu_entry == tu_entry);
            hs_entry->next = cl_addr;

        } else if(random_chance(tu_entry->reuse_conf.value(), tu_entry->replace_rate.value())) {
            HistorySamplerEntry* victim_hs_entry = find_victim<HistorySamplerEntry>(history_sampler, tu_entry->get_last_addr());
            TrainingUnitEntry* victim_hs_tu_entry = training_unit->find_entry(victim_hs_entry->pc, false);
            if(victim_hs_tu_entry != nullptr) {
                victim_hs_tu_entry->hs_entries_evicted++;
                int64_t distance = victim_hs_tu_entry->local_timestamp - victim_hs_entry->local_timestamp;
                if(distance > max_size) {
                    // TODO: TU Access
                    if(!victim_hs_entry->reused) {
                        update_reuse_conf(victim_hs_tu_entry, false);
                        victim_hs_tu_entry->reuse_hs_evict_dec++;
                    }
                    tu_entry->replace_rate++;
                    tu_entry->replace_evict_old_inc++;
                } else if(distance > 0 && !victim_hs_entry->reused) {
                    tu_entry->replace_rate--;
                    tu_entry->replace_evict_young_dec++;
                }
            }

            // Insert HS Entry
            victim_hs_entry->pc = tu_entry->pc;
            victim_hs_entry->next = cl_addr;
            victim_hs_entry->reused = false;
            victim_hs_entry->local_timestamp = tu_entry->local_timestamp + 1;
            // victim_hs_entry->update(cl_addr);
            victim_hs_entry->update(tu_entry->get_last_addr());
            tu_entry->hs_entries++;
        }
    }

    void print() {
        printf("|GHC GPC GRC|HSSVi  HSVi|SCSVi  SCVi|\n");
        printf("|%3u %3u %3u|%5lu %5lu|%5lu %5lu|\n",
            global_high_pattern_conf.value(), global_pattern_conf.value(), global_reuse_conf.value(),
            HistorySamplerEntry::self_victims, HistorySamplerEntry::victims,
            SecondChanceSamplerEntry::self_victims, SecondChanceSamplerEntry::victims
        );
        training_unit->print_triangel();
    }
};

class SRRIP {
    uint64_t num_sets, num_ways;
    std::vector<std::vector<uint8_t>> rrpv = {};
    std::vector<std::vector<bool>> valid = {};
    uint8_t srrip_max = 3, srrip_long = 2;

public:
    SRRIP(uint64_t _num_sets, uint64_t _num_ways): num_sets(_num_sets), num_ways(_num_ways) {
        rrpv.resize(num_sets);
        for(uint64_t set = 0; set < num_sets; set++) {
            rrpv.at(set).resize(num_ways, srrip_max);
        }
    }

    uint64_t find_victim(uint64_t set, std::vector<champsim::block_number> set_data) {
        uint64_t evict_way = num_ways;
        int8_t evict_rrpv = -1;
        for(auto way = 0; way < num_ways; way++) {
            if(rrpv.at(set).at(way) > evict_rrpv) {
                evict_rrpv = rrpv.at(set).at(way);
                evict_way = way;
            }
        }
        for(auto way = 0; way < num_ways; way++) {
            rrpv.at(set).at(way) += (srrip_max - evict_rrpv);
        }
        return evict_way;
    }

    void update_replacement_state(champsim::address pc, uint64_t set, uint64_t way, bool hit, champsim::block_number addr) {
        if(hit) {
            rrpv.at(set).at(way) = 0;
        } else { // Insertion
            rrpv.at(set).at(way) = srrip_long;
        }
    }
};

struct MetadataCacheTriangel {
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
    SRRIP srrip;

    MetadataCacheTriangel(CACHE* _llc_cache, uint64_t _metadata_ways_per_set): llc_cache(_llc_cache), metadata_ways_per_set(_metadata_ways_per_set), total_metadata_ways(llc_cache->NUM_SET * _metadata_ways_per_set), srrip(total_metadata_ways, entries_per_way) {
        entries.resize(total_metadata_ways, std::vector<MetadataEntry>(entries_per_way));
    }

    uint64_t get_idx(champsim::block_number trigger, uint64_t num_ways) {
        uint64_t t = addr_hash_triangel(trigger.to<uint64_t>());
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
            entry = srrip.find_victim(entry_idx, set_data);

            // Set is_metadata as needed
            auto block_idx = get_block_idx(trigger);
            llc_cache->block.at(block_idx).metadata = true;
            llc_cache->block.at(block_idx).valid = false;
            llc_cache->block.at(block_idx).address = champsim::address{0};
        }

        // Update entry with new data
        entries.at(entry_idx).at(entry).update(trigger, pf);
        srrip.update_replacement_state(pc, entry_idx, entry, hit, trigger);
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

struct triangel : public champsim::modules::prefetcher {
    uint64_t ii = 0;
    using prefetcher::prefetcher;
    MetadataReuseBuffer* mrb;
    TrainingUnit* training_unit;
    Triangel* triangel;
    MetadataCacheTriangel* metadata_cache = nullptr;

    champsim::block_number predict(champsim::block_number block_addr);
    void prefetcher_initialize();
    uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address pc, uint8_t cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in);
    uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
};

#endif
