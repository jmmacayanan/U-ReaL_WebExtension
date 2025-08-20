"""
Test script for the Gmail URL Scanner backend server
"""
import requests
import json

BACKEND_URL = 'http://localhost:5000'

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    try:
        response = requests.get(f'{BACKEND_URL}/health')
        print(f"✅ Health check: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")

def test_single_url():
    """Test single URL checking"""
    print("\n🔍 Testing single URL endpoint...")
    
    test_urls = [
        "https://www.google.com",  # Should be benign (whitelisted)
        "http://secure-login-update.com",  # Should be malicious
        "https://facebook.com",  # Should be benign (whitelisted)
        "http://free-money-now.ru"  # Should be malicious
    ]
    
    for url in test_urls:
        try:
            response = requests.post(f'{BACKEND_URL}/check-url', 
                                   json={'url': url, 'threshold': 0.4})
            
            if response.status_code == 200:
                result = response.json()
                status = "🔴 MALICIOUS" if result['is_malicious'] else "🟢 BENIGN"
                print(f"   {status} - {url}")
                print(f"      Confidence: {result['confidence']*100:.2f}%")
                print(f"      Status: {result['status']}")
            else:
                print(f"❌ Error checking {url}: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Failed to check {url}: {e}")

def test_multiple_urls():
    """Test multiple URLs endpoint"""
    print("\n🔍 Testing multiple URLs endpoint...")
    
    urls = [
        "https://www.google.com",
        "http://secure-login-update.com", 
        "https://github.com",
        "http://suspicious-bank-site.ru",
        "https://dataoverhaulers.com/phishing-link-clicked/",
        "https://zbadac.cfd/pl",
        "https://cecauf.com.ar/ul/",
        "https://www.facebook.com/jerneybryant.macayanan",
        "https://film.kace.dev",
        "https://strato-faktur.uccvt.org/DRP140269580/"
    ]
    
    try:
        response = requests.post(f'{BACKEND_URL}/check-urls',
                               json={'urls': urls, 'threshold': 0.4})
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Batch check completed")
            print(f"   Total checked: {data['total_checked']}")
            print(f"   Malicious found: {data['malicious_count']}")
            
            for result in data['results']:
                status = "🔴 MALICIOUS" if result['is_malicious'] else "🟢 BENIGN"
                print(f"   {status} - {result['url']} ({result['confidence']*100:.1f}%)")
        else:
            print(f"❌ Batch check failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Batch check error: {e}")


if __name__ == '__main__':
    print("🧪 Gmail URL Scanner Backend Test Suite")
    print("="*50)
    
    test_health()
    test_single_url() 
    test_multiple_urls()
    
    print("\n✅ Test suite completed!")
    print("\nTo test manually with curl:")
    print(f"curl -X POST {BACKEND_URL}/check-url \\")
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"url": "http://suspicious-site.com"}\'')