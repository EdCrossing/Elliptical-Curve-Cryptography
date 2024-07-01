from ECC_post_lectures import EllipticCurve

# Define the elliptic curve parameters
a = 2
b = 2
p = 17
domain_point = (5, 1)

# Create an instance of the EllipticCurve class
curve = EllipticCurve(a, b, p, domain_point)

# Test functions

def test_point_add():
    """
    Test point addition on the elliptic curve.
    """
    point1 = (3, 16)
    point2 = (5, 1)
    expected_result = (10, 11)  # Expected result of adding (5, 1) + (5, 1) on the given curve
    try:
        result = curve.point_add(point1, point2)
        assert result == expected_result, f"Expected {expected_result}, got {result}"
        print("Point addition test passed.")
    except Exception as e:
        print(f"Point addition test failed: {e}")

def test_point_double():
    """
    Test point doubling on the elliptic curve.
    """
    point = (9, 16)
    expected_result = (7, 11)  # Expected result of doubling (5, 1) on the given curve
    try:
        result = curve.point_double(point)
        assert result == expected_result, f"Expected {expected_result}, got {result}"
        print("Point doubling test passed.")
    except Exception as e:
        print(f"Point doubling test failed: {e}")

def test_gen_pubkey():
    """
    Test public key generation.
    """
    prv_key = 10
    expected_pub_key = (7, 11)  # Expected result of multiplying the domain point by 10 on the given curve
    try:
        pub_key = curve.gen_pubkey(prv_key)
        assert pub_key == expected_pub_key, f"Expected {expected_pub_key}, got {pub_key}"
        print("Public key generation test passed.")
    except Exception as e:
        print(f"Public key generation test failed: {e}")

def test_gen_shared_secret():
    """
    Test shared secret generation.
    """
    prv_key_a = 5
    prv_key_b = 7
    pub_key_a = curve.gen_pubkey(prv_key_a)
    pub_key_b = curve.gen_pubkey(prv_key_b)
    try:
        shared_secret_a = curve.gen_shared_secret(prv_key_a, pub_key_b)
        shared_secret_b = curve.gen_shared_secret(prv_key_b, pub_key_a)
        assert shared_secret_a == shared_secret_b, f"Expected {shared_secret_a} to equal {shared_secret_b} :( )"
        print("Shared secret generation test passed.")
    except Exception as e:
        print(f"Shared secret generation test failed: {e}")

# Run tests
if __name__ == "__main__":
    test_point_add()
    test_point_double()
    test_gen_pubkey()
    test_gen_shared_secret()