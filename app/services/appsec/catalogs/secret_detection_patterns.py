"""
SecureVault Secret Detection Regular Expression Catalog
"""

SECRET_DETECTION_PATTERNS = [
    {
        'secret_type': 'AWS_ACCESS_KEY',
        'regex_pattern': r'\b(AKIA[0-9A-Z]{16})\b',
        'severity': 'CRITICAL',
        'confidence_score': 99,
        'description': 'Detects hardcoded Aws Access Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'AWS_SECRET_KEY',
        'regex_pattern': r'\b([0-9a-zA-Z/+]{40})\b',
        'severity': 'HIGH',
        'confidence_score': 80,
        'description': 'Detects hardcoded Aws Secret Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'GITHUB_PAT',
        'regex_pattern': r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b',
        'severity': 'CRITICAL',
        'confidence_score': 99,
        'description': 'Detects hardcoded Github Pat in plaintext code and configurations.'
    },
    {
        'secret_type': 'GITHUB_OAUTH',
        'regex_pattern': r'\b(gho_[a-zA-Z0-9]{36})\b',
        'severity': 'CRITICAL',
        'confidence_score': 99,
        'description': 'Detects hardcoded Github Oauth in plaintext code and configurations.'
    },
    {
        'secret_type': 'SLACK_BOT_TOKEN',
        'regex_pattern': r'\b(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24})\b',
        'severity': 'HIGH',
        'confidence_score': 98,
        'description': 'Detects hardcoded Slack Bot Token in plaintext code and configurations.'
    },
    {
        'secret_type': 'SLACK_WEBHOOK',
        'regex_pattern': r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+',
        'severity': 'HIGH',
        'confidence_score': 95,
        'description': 'Detects hardcoded Slack Webhook in plaintext code and configurations.'
    },
    {
        'secret_type': 'STRIPE_API_KEY',
        'regex_pattern': r'\b(sk_live_[0-9a-zA-Z]{24})\b',
        'severity': 'CRITICAL',
        'confidence_score': 98,
        'description': 'Detects hardcoded Stripe Api Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'SENDGRID_API_KEY',
        'regex_pattern': r'\b(SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43})\b',
        'severity': 'HIGH',
        'confidence_score': 95,
        'description': 'Detects hardcoded Sendgrid Api Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'TWILIO_API_KEY',
        'regex_pattern': r'\b(SK[0-9a-fA-F]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Detects hardcoded Twilio Api Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'OPENAI_API_KEY',
        'regex_pattern': r'\b(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_-]{80,})\b',
        'severity': 'CRITICAL',
        'confidence_score': 95,
        'description': 'Detects hardcoded Openai Api Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'HUGGINGFACE_TOKEN',
        'regex_pattern': r'\b(hf_[a-zA-Z0-9]{34})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Detects hardcoded Huggingface Token in plaintext code and configurations.'
    },
    {
        'secret_type': 'RSA_PRIVATE_KEY',
        'regex_pattern': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
        'severity': 'CRITICAL',
        'confidence_score': 100,
        'description': 'Detects hardcoded Rsa Private Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'OPENSSH_PRIVATE_KEY',
        'regex_pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'severity': 'CRITICAL',
        'confidence_score': 100,
        'description': 'Detects hardcoded Openssh Private Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'PGP_PRIVATE_KEY',
        'regex_pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'severity': 'CRITICAL',
        'confidence_score': 100,
        'description': 'Detects hardcoded Pgp Private Key in plaintext code and configurations.'
    },
    {
        'secret_type': 'JWT_BEARER_TOKEN',
        'regex_pattern': r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Detects hardcoded Jwt Bearer Token in plaintext code and configurations.'
    },
    {
        'secret_type': 'GENERIC_DATABASE_URI',
        'regex_pattern': r'(mysql|postgres|postgresql|mongodb|redis):\/\/[^:]+:([^@]+)@',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Detects hardcoded Generic Database Uri in plaintext code and configurations.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_01',
        'regex_pattern': r'\b(cloud_api_key_01_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #01.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_02',
        'regex_pattern': r'\b(cloud_api_key_02_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #02.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_03',
        'regex_pattern': r'\b(cloud_api_key_03_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #03.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_04',
        'regex_pattern': r'\b(cloud_api_key_04_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #04.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_05',
        'regex_pattern': r'\b(cloud_api_key_05_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #05.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_06',
        'regex_pattern': r'\b(cloud_api_key_06_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #06.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_07',
        'regex_pattern': r'\b(cloud_api_key_07_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #07.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_08',
        'regex_pattern': r'\b(cloud_api_key_08_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #08.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_09',
        'regex_pattern': r'\b(cloud_api_key_09_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #09.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_10',
        'regex_pattern': r'\b(cloud_api_key_10_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #10.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_11',
        'regex_pattern': r'\b(cloud_api_key_11_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #11.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_12',
        'regex_pattern': r'\b(cloud_api_key_12_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #12.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_13',
        'regex_pattern': r'\b(cloud_api_key_13_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #13.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_14',
        'regex_pattern': r'\b(cloud_api_key_14_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #14.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_15',
        'regex_pattern': r'\b(cloud_api_key_15_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #15.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_16',
        'regex_pattern': r'\b(cloud_api_key_16_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #16.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_17',
        'regex_pattern': r'\b(cloud_api_key_17_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #17.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_18',
        'regex_pattern': r'\b(cloud_api_key_18_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #18.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_19',
        'regex_pattern': r'\b(cloud_api_key_19_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #19.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_20',
        'regex_pattern': r'\b(cloud_api_key_20_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #20.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_21',
        'regex_pattern': r'\b(cloud_api_key_21_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #21.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_22',
        'regex_pattern': r'\b(cloud_api_key_22_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #22.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_23',
        'regex_pattern': r'\b(cloud_api_key_23_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #23.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_24',
        'regex_pattern': r'\b(cloud_api_key_24_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #24.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_25',
        'regex_pattern': r'\b(cloud_api_key_25_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #25.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_26',
        'regex_pattern': r'\b(cloud_api_key_26_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #26.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_27',
        'regex_pattern': r'\b(cloud_api_key_27_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #27.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_28',
        'regex_pattern': r'\b(cloud_api_key_28_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #28.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_29',
        'regex_pattern': r'\b(cloud_api_key_29_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #29.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_30',
        'regex_pattern': r'\b(cloud_api_key_30_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #30.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_31',
        'regex_pattern': r'\b(cloud_api_key_31_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #31.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_32',
        'regex_pattern': r'\b(cloud_api_key_32_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #32.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_33',
        'regex_pattern': r'\b(cloud_api_key_33_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #33.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_34',
        'regex_pattern': r'\b(cloud_api_key_34_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #34.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_35',
        'regex_pattern': r'\b(cloud_api_key_35_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #35.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_36',
        'regex_pattern': r'\b(cloud_api_key_36_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #36.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_37',
        'regex_pattern': r'\b(cloud_api_key_37_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #37.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_38',
        'regex_pattern': r'\b(cloud_api_key_38_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #38.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_39',
        'regex_pattern': r'\b(cloud_api_key_39_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #39.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_40',
        'regex_pattern': r'\b(cloud_api_key_40_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #40.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_41',
        'regex_pattern': r'\b(cloud_api_key_41_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #41.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_42',
        'regex_pattern': r'\b(cloud_api_key_42_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #42.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_43',
        'regex_pattern': r'\b(cloud_api_key_43_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #43.'
    },
    {
        'secret_type': 'CLOUD_TOKEN_TYPE_44',
        'regex_pattern': r'\b(cloud_api_key_44_[0-9a-zA-Z]{32})\b',
        'severity': 'HIGH',
        'confidence_score': 90,
        'description': 'Enterprise API token pattern for SaaS service #44.'
    },
]

def get_all_secret_patterns():
    return SECRET_DETECTION_PATTERNS
