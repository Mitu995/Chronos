from chronos.crack_time import estimate_all_scenarios, estimate_crack_time


def test_higher_entropy_takes_longer():
    weak = estimate_crack_time(20, hash_type="MD5", scenario="offline_single_gpu")
    strong = estimate_crack_time(80, hash_type="MD5", scenario="offline_single_gpu")
    assert strong.seconds_to_crack > weak.seconds_to_crack


def test_slow_hash_takes_longer_than_fast_hash_at_same_entropy():
    md5_estimate = estimate_crack_time(40, hash_type="MD5", scenario="offline_single_gpu")
    bcrypt_estimate = estimate_crack_time(40, hash_type="bcrypt", scenario="offline_single_gpu")
    assert bcrypt_estimate.seconds_to_crack > md5_estimate.seconds_to_crack


def test_gpu_cluster_faster_than_single_gpu():
    single = estimate_crack_time(50, hash_type="SHA-256", scenario="offline_single_gpu")
    cluster = estimate_crack_time(50, hash_type="SHA-256", scenario="offline_gpu_cluster")
    assert cluster.seconds_to_crack < single.seconds_to_crack


def test_online_throttled_ignores_hash_type():
    a = estimate_crack_time(30, hash_type="MD5", scenario="online_throttled")
    b = estimate_crack_time(30, hash_type="bcrypt", scenario="online_throttled")
    assert a.seconds_to_crack == b.seconds_to_crack


def test_unknown_scenario_raises():
    try:
        estimate_crack_time(30, scenario="not_a_real_scenario")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_estimate_all_scenarios_returns_three():
    results = estimate_all_scenarios(40, hash_type="SHA-1")
    assert len(results) == 3


def test_human_readable_instant_for_trivial_entropy():
    result = estimate_crack_time(1, hash_type="MD5", scenario="offline_single_gpu")
    assert "instant" in result.human_readable or "second" in result.human_readable
