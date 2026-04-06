"""
Fingerprints for subdomain takeover detection.
Each entry maps a service to its CNAME patterns and HTTP response signatures
that indicate the service is unclaimed.
"""

CNAME_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "http_body": ["There isn't a GitHub Pages site here"],
        "http_status": [404],
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokudns.com", "herokussl.com", "herokuapp.com"],
        "http_body": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "http_status": [404],
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.com", "netlify.app"],
        "http_body": ["Not Found - Request ID"],
        "http_status": [404],
    },
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "http_body": ["NoSuchBucket", "The specified bucket does not exist"],
        "http_status": [404],
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "http_body": ["Fastly error: unknown domain"],
        "http_status": [404],
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "http_body": ["Sorry, this shop is currently unavailable"],
        "http_status": [404],
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "http_body": ["Whatever you were looking for doesn't currently exist at this address"],
        "http_status": [404],
    },
    {
        "service": "WordPress",
        "cname_patterns": ["wordpress.com"],
        "http_body": ["Do you want to register"],
        "http_status": [404],
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "http_body": ["project not found"],
        "http_status": [404],
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "http_body": ["Help Center Closed"],
        "http_status": [404],
    },
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.net", "hubspotpagebuilder.com"],
        "http_body": ["Domain not found"],
        "http_status": [404],
    },
    {
        "service": "Azure",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "http_body": ["404 Web Site not found"],
        "http_status": [404],
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "vercel.com"],
        "http_body": ["The deployment could not be found"],
        "http_status": [404],
    },
    {
        "service": "Cargo",
        "cname_patterns": ["cargocollective.com"],
        "http_body": ["404 Not Found"],
        "http_status": [404],
    },
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev"],
        "http_body": ["404 Not Found"],
        "http_status": [404],
    },
]

# Known AWS regions for S3 bucket brute-forcing
S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ap-south-1", "sa-east-1", "ca-central-1",
]
