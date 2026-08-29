"""
SecureVault Post-Quantum Cryptography (PQC) KEM & Digital Signature Matrix
FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), FIPS 205 (SLH-DSA / SPHINCS+)
"""

PQC_STANDARDS_MATRIX = [
    {
        'pqc_id': 'PQC-SPEC-001',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 802,
        'ciphertext_size_bytes': 770,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-002',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 804,
        'ciphertext_size_bytes': 772,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-003',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 806,
        'ciphertext_size_bytes': 774,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-004',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 808,
        'ciphertext_size_bytes': 776,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-005',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 810,
        'ciphertext_size_bytes': 778,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-006',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 812,
        'ciphertext_size_bytes': 780,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-007',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 814,
        'ciphertext_size_bytes': 782,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-008',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 816,
        'ciphertext_size_bytes': 784,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-009',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 818,
        'ciphertext_size_bytes': 786,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-010',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 820,
        'ciphertext_size_bytes': 788,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-011',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 822,
        'ciphertext_size_bytes': 790,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-012',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 824,
        'ciphertext_size_bytes': 792,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-013',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 826,
        'ciphertext_size_bytes': 794,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-014',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 828,
        'ciphertext_size_bytes': 796,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-015',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 830,
        'ciphertext_size_bytes': 798,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-016',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 832,
        'ciphertext_size_bytes': 800,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-017',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 834,
        'ciphertext_size_bytes': 802,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-018',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 836,
        'ciphertext_size_bytes': 804,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-019',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 838,
        'ciphertext_size_bytes': 806,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-020',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 840,
        'ciphertext_size_bytes': 808,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-021',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 842,
        'ciphertext_size_bytes': 810,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-022',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 844,
        'ciphertext_size_bytes': 812,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-023',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 846,
        'ciphertext_size_bytes': 814,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-024',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 848,
        'ciphertext_size_bytes': 816,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-025',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 850,
        'ciphertext_size_bytes': 818,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-026',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 852,
        'ciphertext_size_bytes': 820,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-027',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 854,
        'ciphertext_size_bytes': 822,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-028',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 856,
        'ciphertext_size_bytes': 824,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-029',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 858,
        'ciphertext_size_bytes': 826,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-030',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 860,
        'ciphertext_size_bytes': 828,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-031',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 862,
        'ciphertext_size_bytes': 830,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-032',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 864,
        'ciphertext_size_bytes': 832,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-033',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 866,
        'ciphertext_size_bytes': 834,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-034',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 868,
        'ciphertext_size_bytes': 836,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-035',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 870,
        'ciphertext_size_bytes': 838,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-036',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 872,
        'ciphertext_size_bytes': 840,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-037',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 874,
        'ciphertext_size_bytes': 842,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-038',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 876,
        'ciphertext_size_bytes': 844,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-039',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 878,
        'ciphertext_size_bytes': 846,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-040',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 880,
        'ciphertext_size_bytes': 848,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-041',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 882,
        'ciphertext_size_bytes': 850,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-042',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 884,
        'ciphertext_size_bytes': 852,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-043',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 886,
        'ciphertext_size_bytes': 854,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-044',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 888,
        'ciphertext_size_bytes': 856,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-045',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 890,
        'ciphertext_size_bytes': 858,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-046',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 892,
        'ciphertext_size_bytes': 860,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-047',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 894,
        'ciphertext_size_bytes': 862,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-048',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 896,
        'ciphertext_size_bytes': 864,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-049',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 898,
        'ciphertext_size_bytes': 866,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-050',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 900,
        'ciphertext_size_bytes': 868,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-051',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 902,
        'ciphertext_size_bytes': 870,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-052',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 904,
        'ciphertext_size_bytes': 872,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-053',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 906,
        'ciphertext_size_bytes': 874,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-054',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 908,
        'ciphertext_size_bytes': 876,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-055',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 910,
        'ciphertext_size_bytes': 878,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-056',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 912,
        'ciphertext_size_bytes': 880,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-057',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 914,
        'ciphertext_size_bytes': 882,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-058',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 916,
        'ciphertext_size_bytes': 884,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-059',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 918,
        'ciphertext_size_bytes': 886,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-060',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 920,
        'ciphertext_size_bytes': 888,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-061',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 922,
        'ciphertext_size_bytes': 890,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-062',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 924,
        'ciphertext_size_bytes': 892,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-063',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 926,
        'ciphertext_size_bytes': 894,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-064',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 928,
        'ciphertext_size_bytes': 896,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-065',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 930,
        'ciphertext_size_bytes': 898,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-066',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 932,
        'ciphertext_size_bytes': 900,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-067',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 934,
        'ciphertext_size_bytes': 902,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-068',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 936,
        'ciphertext_size_bytes': 904,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-069',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 938,
        'ciphertext_size_bytes': 906,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-070',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 940,
        'ciphertext_size_bytes': 908,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-071',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 942,
        'ciphertext_size_bytes': 910,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-072',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 944,
        'ciphertext_size_bytes': 912,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-073',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 946,
        'ciphertext_size_bytes': 914,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-074',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 948,
        'ciphertext_size_bytes': 916,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-075',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 950,
        'ciphertext_size_bytes': 918,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-076',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 952,
        'ciphertext_size_bytes': 920,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-077',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 954,
        'ciphertext_size_bytes': 922,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-078',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 956,
        'ciphertext_size_bytes': 924,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-079',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 958,
        'ciphertext_size_bytes': 926,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-080',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 960,
        'ciphertext_size_bytes': 928,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-081',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 962,
        'ciphertext_size_bytes': 930,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-082',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 964,
        'ciphertext_size_bytes': 932,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-083',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 966,
        'ciphertext_size_bytes': 934,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-084',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 968,
        'ciphertext_size_bytes': 936,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-085',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 970,
        'ciphertext_size_bytes': 938,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-086',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 972,
        'ciphertext_size_bytes': 940,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-087',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 974,
        'ciphertext_size_bytes': 942,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-088',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 976,
        'ciphertext_size_bytes': 944,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-089',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 978,
        'ciphertext_size_bytes': 946,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-090',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 980,
        'ciphertext_size_bytes': 948,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-091',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 982,
        'ciphertext_size_bytes': 950,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-092',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 984,
        'ciphertext_size_bytes': 952,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-093',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 986,
        'ciphertext_size_bytes': 954,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-094',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 988,
        'ciphertext_size_bytes': 956,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-095',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 990,
        'ciphertext_size_bytes': 958,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-096',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 992,
        'ciphertext_size_bytes': 960,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-097',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 994,
        'ciphertext_size_bytes': 962,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-098',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 996,
        'ciphertext_size_bytes': 964,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-099',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 998,
        'ciphertext_size_bytes': 966,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-100',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1000,
        'ciphertext_size_bytes': 968,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-101',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1002,
        'ciphertext_size_bytes': 970,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-102',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1004,
        'ciphertext_size_bytes': 972,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-103',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1006,
        'ciphertext_size_bytes': 974,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-104',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1008,
        'ciphertext_size_bytes': 976,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-105',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1010,
        'ciphertext_size_bytes': 978,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-106',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1012,
        'ciphertext_size_bytes': 980,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-107',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1014,
        'ciphertext_size_bytes': 982,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-108',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1016,
        'ciphertext_size_bytes': 984,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-109',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1018,
        'ciphertext_size_bytes': 986,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-110',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1020,
        'ciphertext_size_bytes': 988,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-111',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1022,
        'ciphertext_size_bytes': 990,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-112',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1024,
        'ciphertext_size_bytes': 992,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-113',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1026,
        'ciphertext_size_bytes': 994,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-114',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1028,
        'ciphertext_size_bytes': 996,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-115',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1030,
        'ciphertext_size_bytes': 998,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-116',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1032,
        'ciphertext_size_bytes': 1000,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-117',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1034,
        'ciphertext_size_bytes': 1002,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-118',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1036,
        'ciphertext_size_bytes': 1004,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-119',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1038,
        'ciphertext_size_bytes': 1006,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-120',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1040,
        'ciphertext_size_bytes': 1008,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-121',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1042,
        'ciphertext_size_bytes': 1010,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-122',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1044,
        'ciphertext_size_bytes': 1012,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-123',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1046,
        'ciphertext_size_bytes': 1014,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-124',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1048,
        'ciphertext_size_bytes': 1016,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-125',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1050,
        'ciphertext_size_bytes': 1018,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-126',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1052,
        'ciphertext_size_bytes': 1020,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-127',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1054,
        'ciphertext_size_bytes': 1022,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-128',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1056,
        'ciphertext_size_bytes': 1024,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-129',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1058,
        'ciphertext_size_bytes': 1026,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-130',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1060,
        'ciphertext_size_bytes': 1028,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-131',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1062,
        'ciphertext_size_bytes': 1030,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-132',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1064,
        'ciphertext_size_bytes': 1032,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-133',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1066,
        'ciphertext_size_bytes': 1034,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-134',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1068,
        'ciphertext_size_bytes': 1036,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-135',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1070,
        'ciphertext_size_bytes': 1038,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-136',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1072,
        'ciphertext_size_bytes': 1040,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-137',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1074,
        'ciphertext_size_bytes': 1042,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-138',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1076,
        'ciphertext_size_bytes': 1044,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-139',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1078,
        'ciphertext_size_bytes': 1046,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-140',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1080,
        'ciphertext_size_bytes': 1048,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-141',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1082,
        'ciphertext_size_bytes': 1050,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-142',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1084,
        'ciphertext_size_bytes': 1052,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-143',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1086,
        'ciphertext_size_bytes': 1054,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-144',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1088,
        'ciphertext_size_bytes': 1056,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-145',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1090,
        'ciphertext_size_bytes': 1058,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-146',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1092,
        'ciphertext_size_bytes': 1060,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-147',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1094,
        'ciphertext_size_bytes': 1062,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-148',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1096,
        'ciphertext_size_bytes': 1064,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-149',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1098,
        'ciphertext_size_bytes': 1066,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-150',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1100,
        'ciphertext_size_bytes': 1068,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-151',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1102,
        'ciphertext_size_bytes': 1070,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-152',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1104,
        'ciphertext_size_bytes': 1072,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-153',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1106,
        'ciphertext_size_bytes': 1074,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-154',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1108,
        'ciphertext_size_bytes': 1076,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-155',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1110,
        'ciphertext_size_bytes': 1078,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-156',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1112,
        'ciphertext_size_bytes': 1080,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-157',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1114,
        'ciphertext_size_bytes': 1082,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-158',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1116,
        'ciphertext_size_bytes': 1084,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-159',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1118,
        'ciphertext_size_bytes': 1086,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-160',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1120,
        'ciphertext_size_bytes': 1088,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-161',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1122,
        'ciphertext_size_bytes': 1090,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-162',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1124,
        'ciphertext_size_bytes': 1092,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-163',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1126,
        'ciphertext_size_bytes': 1094,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-164',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1128,
        'ciphertext_size_bytes': 1096,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-165',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1130,
        'ciphertext_size_bytes': 1098,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-166',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1132,
        'ciphertext_size_bytes': 1100,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-167',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1134,
        'ciphertext_size_bytes': 1102,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-168',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1136,
        'ciphertext_size_bytes': 1104,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-169',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1138,
        'ciphertext_size_bytes': 1106,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-170',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1140,
        'ciphertext_size_bytes': 1108,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-171',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1142,
        'ciphertext_size_bytes': 1110,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-172',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1144,
        'ciphertext_size_bytes': 1112,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-173',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1146,
        'ciphertext_size_bytes': 1114,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-174',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1148,
        'ciphertext_size_bytes': 1116,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-175',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1150,
        'ciphertext_size_bytes': 1118,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-176',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1152,
        'ciphertext_size_bytes': 1120,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-177',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1154,
        'ciphertext_size_bytes': 1122,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-178',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1156,
        'ciphertext_size_bytes': 1124,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-179',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1158,
        'ciphertext_size_bytes': 1126,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-180',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1160,
        'ciphertext_size_bytes': 1128,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-181',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1162,
        'ciphertext_size_bytes': 1130,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-182',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1164,
        'ciphertext_size_bytes': 1132,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-183',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1166,
        'ciphertext_size_bytes': 1134,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-184',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1168,
        'ciphertext_size_bytes': 1136,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-185',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1170,
        'ciphertext_size_bytes': 1138,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-186',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1172,
        'ciphertext_size_bytes': 1140,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-187',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1174,
        'ciphertext_size_bytes': 1142,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-188',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1176,
        'ciphertext_size_bytes': 1144,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-189',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1178,
        'ciphertext_size_bytes': 1146,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-190',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1180,
        'ciphertext_size_bytes': 1148,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-191',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1182,
        'ciphertext_size_bytes': 1150,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-192',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1184,
        'ciphertext_size_bytes': 1152,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-193',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1186,
        'ciphertext_size_bytes': 1154,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-194',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1188,
        'ciphertext_size_bytes': 1156,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-195',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1190,
        'ciphertext_size_bytes': 1158,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-196',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1192,
        'ciphertext_size_bytes': 1160,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-197',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1194,
        'ciphertext_size_bytes': 1162,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-198',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1196,
        'ciphertext_size_bytes': 1164,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-199',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1198,
        'ciphertext_size_bytes': 1166,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-200',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1200,
        'ciphertext_size_bytes': 1168,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-201',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1202,
        'ciphertext_size_bytes': 1170,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-202',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1204,
        'ciphertext_size_bytes': 1172,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-203',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1206,
        'ciphertext_size_bytes': 1174,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-204',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1208,
        'ciphertext_size_bytes': 1176,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-205',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1210,
        'ciphertext_size_bytes': 1178,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-206',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1212,
        'ciphertext_size_bytes': 1180,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-207',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1214,
        'ciphertext_size_bytes': 1182,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-208',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1216,
        'ciphertext_size_bytes': 1184,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-209',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1218,
        'ciphertext_size_bytes': 1186,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-210',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1220,
        'ciphertext_size_bytes': 1188,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-211',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1222,
        'ciphertext_size_bytes': 1190,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-212',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1224,
        'ciphertext_size_bytes': 1192,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-213',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1226,
        'ciphertext_size_bytes': 1194,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-214',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1228,
        'ciphertext_size_bytes': 1196,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-215',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1230,
        'ciphertext_size_bytes': 1198,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-216',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1232,
        'ciphertext_size_bytes': 1200,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-217',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1234,
        'ciphertext_size_bytes': 1202,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-218',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1236,
        'ciphertext_size_bytes': 1204,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-219',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1238,
        'ciphertext_size_bytes': 1206,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-220',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1240,
        'ciphertext_size_bytes': 1208,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-221',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1242,
        'ciphertext_size_bytes': 1210,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-222',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1244,
        'ciphertext_size_bytes': 1212,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-223',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1246,
        'ciphertext_size_bytes': 1214,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-224',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1248,
        'ciphertext_size_bytes': 1216,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-225',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1250,
        'ciphertext_size_bytes': 1218,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-226',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1252,
        'ciphertext_size_bytes': 1220,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-227',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1254,
        'ciphertext_size_bytes': 1222,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-228',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1256,
        'ciphertext_size_bytes': 1224,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-229',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1258,
        'ciphertext_size_bytes': 1226,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-230',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1260,
        'ciphertext_size_bytes': 1228,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-231',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1262,
        'ciphertext_size_bytes': 1230,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-232',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1264,
        'ciphertext_size_bytes': 1232,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-233',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1266,
        'ciphertext_size_bytes': 1234,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-234',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1268,
        'ciphertext_size_bytes': 1236,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-235',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1270,
        'ciphertext_size_bytes': 1238,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-236',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1272,
        'ciphertext_size_bytes': 1240,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-237',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1274,
        'ciphertext_size_bytes': 1242,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-238',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1276,
        'ciphertext_size_bytes': 1244,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-239',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1278,
        'ciphertext_size_bytes': 1246,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-240',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1280,
        'ciphertext_size_bytes': 1248,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-241',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1282,
        'ciphertext_size_bytes': 1250,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-242',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1284,
        'ciphertext_size_bytes': 1252,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-243',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1286,
        'ciphertext_size_bytes': 1254,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-244',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1288,
        'ciphertext_size_bytes': 1256,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-245',
        'algorithm_name': 'ML-KEM-512 (Kyber-512)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 1,
        'public_key_size_bytes': 1290,
        'ciphertext_size_bytes': 1258,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-246',
        'algorithm_name': 'ML-KEM-768 (Kyber-768)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 3,
        'public_key_size_bytes': 1292,
        'ciphertext_size_bytes': 1260,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-247',
        'algorithm_name': 'ML-KEM-1024 (Kyber-1024)',
        'fips_standard': 'FIPS 203',
        'nist_security_level': 5,
        'public_key_size_bytes': 1294,
        'ciphertext_size_bytes': 1262,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-248',
        'algorithm_name': 'ML-DSA-65 (Dilithium3)',
        'fips_standard': 'FIPS 204',
        'nist_security_level': 3,
        'public_key_size_bytes': 1296,
        'ciphertext_size_bytes': 1264,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
    {
        'pqc_id': 'PQC-SPEC-249',
        'algorithm_name': 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        'fips_standard': 'FIPS 205',
        'nist_security_level': 1,
        'public_key_size_bytes': 1298,
        'ciphertext_size_bytes': 1266,
        'hybrid_classical_pairing': 'X25519 / RSA-4096',
        'readiness_status': 'ACTIVE'
    },
]

def get_all_pqc_standards():
    return PQC_STANDARDS_MATRIX
