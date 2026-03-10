#include <catch.hpp>
#include <map>
#include <vector>

#include "cache.h"
#include "defaults.hpp"
#include "mocks.hpp"
#include "modules.h"

namespace
{
struct origin_operate_call {
  champsim::address addr;
  bool cache_hit;
  bool late_prefetch;
  bool origin_prefetch_from_this;
  access_type type;
};

std::map<CACHE*, std::vector<origin_operate_call>> origin_operate_collector;
}

struct origin_collector : champsim::modules::prefetcher {
  using prefetcher::prefetcher;

  uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address, uint8_t cache_hit, bool, access_type type, uint32_t metadata_in,
                                    bool late_prefetch, bool origin_prefetch_from_this)
  {
    ::origin_operate_collector[intern_].push_back({addr, static_cast<bool>(cache_hit), late_prefetch, origin_prefetch_from_this, type});
    return metadata_in;
  }

  uint32_t prefetcher_cache_fill(champsim::address, long, long, uint8_t, champsim::address, uint32_t metadata_in) { return metadata_in; }
};

SCENARIO("A promoted prefetch MSHR keeps local-prefetch provenance")
{
  GIVEN("A cache with an in-flight local prefetch")
  {
    constexpr uint64_t hit_latency = 2;
    constexpr uint64_t fill_latency = 2;
    constexpr champsim::address test_addr{0xdeadbeef};

    release_MRC mock_ll;
    to_rq_MRP mock_ul;
    CACHE uut{champsim::cache_builder{champsim::defaults::default_l1d}
                  .name("433-uut")
                  .upper_levels({&mock_ul.queues})
                  .lower_level(&mock_ll.queues)
                  .hit_latency(hit_latency)
                  .fill_latency(fill_latency)
                  .prefetcher<origin_collector>()};

    std::array<champsim::operable*, 3> elements{{&mock_ll, &mock_ul, &uut}};

    for (auto elem : elements) {
      elem->initialize();
      elem->warmup = false;
      elem->begin_phase();
    }

    auto run_cycles = [&](uint64_t count) {
      for (uint64_t i = 0; i < count; ++i)
        for (auto elem : elements)
          elem->_operate();
    };

    auto issue_load = [&](uint64_t instr_id) {
      decltype(mock_ul)::request_type pkt;
      pkt.address = test_addr;
      pkt.v_address = test_addr;
      pkt.metadata = false;
      pkt.cpu = 0;
      pkt.type = access_type::LOAD;
      pkt.instr_id = instr_id;

      auto accepted = mock_ul.issue(pkt);
      REQUIRE(accepted);
      run_cycles(hit_latency + 2);
    };

    ::origin_operate_collector.insert_or_assign(&uut, std::vector<origin_operate_call>{});

    REQUIRE(uut.prefetch_line(test_addr, true, 0));
    run_cycles(16);

    REQUIRE(mock_ll.packet_count() == 1);
    REQUIRE_THAT(uut.MSHR, Catch::Matchers::SizeIs(1));
    REQUIRE(uut.MSHR.front().type == access_type::PREFETCH);
    REQUIRE(uut.MSHR.front().origin_prefetch_from_this);

    WHEN("Two loads merge into that in-flight prefetch before the fill returns")
    {
      issue_load(1);
      issue_load(2);

      THEN("Both loads are still classified as late local-prefetch accesses")
      {
        REQUIRE_THAT(::origin_operate_collector.at(&uut), Catch::Matchers::SizeIs(2));
        CHECK(::origin_operate_collector.at(&uut).at(0).addr == test_addr);
        CHECK_FALSE(::origin_operate_collector.at(&uut).at(0).cache_hit);
        CHECK(::origin_operate_collector.at(&uut).at(0).late_prefetch);
        CHECK(::origin_operate_collector.at(&uut).at(0).origin_prefetch_from_this);

        CHECK(::origin_operate_collector.at(&uut).at(1).addr == test_addr);
        CHECK_FALSE(::origin_operate_collector.at(&uut).at(1).cache_hit);
        CHECK(::origin_operate_collector.at(&uut).at(1).late_prefetch);
        CHECK(::origin_operate_collector.at(&uut).at(1).origin_prefetch_from_this);
      }

      THEN("The promoted MSHR still carries the local-prefetch origin bit")
      {
        REQUIRE_THAT(uut.MSHR, Catch::Matchers::SizeIs(1));
        CHECK(uut.MSHR.front().type == access_type::LOAD);
        CHECK(uut.MSHR.front().origin_prefetch_from_this);
      }

      AND_WHEN("The fill returns and later accesses hit in the cache")
      {
        mock_ll.release_all();
        run_cycles(16);

        REQUIRE_THAT(uut.MSHR, Catch::Matchers::SizeIs(0));

        issue_load(3);
        issue_load(4);

        THEN("The first cache hit sees the origin bit and the second one does not")
        {
          REQUIRE_THAT(::origin_operate_collector.at(&uut), Catch::Matchers::SizeIs(4));

          CHECK(::origin_operate_collector.at(&uut).at(2).cache_hit);
          CHECK_FALSE(::origin_operate_collector.at(&uut).at(2).late_prefetch);
          CHECK(::origin_operate_collector.at(&uut).at(2).origin_prefetch_from_this);

          CHECK(::origin_operate_collector.at(&uut).at(3).cache_hit);
          CHECK_FALSE(::origin_operate_collector.at(&uut).at(3).late_prefetch);
          CHECK_FALSE(::origin_operate_collector.at(&uut).at(3).origin_prefetch_from_this);
        }
      }
    }
  }
}
