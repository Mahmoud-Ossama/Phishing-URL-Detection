# Phishing URL Examples for Testing

## ⚠️ **EDUCATIONAL USE ONLY** ⚠️
These URLs are for testing phishing detection systems and security awareness training.
**DO NOT USE THESE FOR MALICIOUS PURPOSES.**

## 1. **Typosquatting Examples**

### Popular Site Variations
- `https://gooogle.com` (Google with extra 'o')
- `https://googel.com` (Google with swapped letters)
- `https://goolge.com` (Google with transposed letters)
- `https://g00gle.com` (Google with zeros)

### Social Media Typosquats
- `https://facabook.com` (Facebook missing 'e')
- `https://facebok.com` (Facebook missing 'o')
- `https://faceebok.com` (Facebook with extra 'e')
- `https://twiter.com` (Twitter missing 't')
- `https://twiiter.com` (Twitter with extra 'i')
- `https://instragram.com` (Instagram with transposed letters)

### E-commerce Typosquats
- `https://amaz0n.com` (Amazon with zero)
- `https://amazom.com` (Amazon with 'm' instead of 'n')
- `https://amazon.co` (Missing TLD extension)
- `https://ebey.com` (eBay misspelled)
- `https://ebaay.com` (eBay with extra 'a')

### Financial Service Typosquats
- `https://payp4l.com` (PayPal with '4')
- `https://paypaI.com` (PayPal with capital 'I' instead of 'l')
- `https://paipal.com` (PayPal with 'i' instead of 'y')

## 2. **Subdomain Spoofing**

### Legitimate-looking Subdomains
- `https://security.google-update.com`
- `https://login.facebook-security.com`
- `https://account.amazon-verify.com`
- `https://update.microsoft-support.com`
- `https://secure.paypal-verification.com`

### Brand Name in Subdomain
- `https://amazon.fake-store.com`
- `https://paypal.secure-login.net`
- `https://google.account-verify.org`
- `https://facebook.security-check.info`

## 3. **URL Shortener Abuse**
- `https://bit.ly/3fake123` (Shortened malicious URL)
- `https://tinyurl.com/phishexample`
- `https://t.co/maliciouslink`

## 4. **IP Address URLs**
- `https://192.168.1.100/secure/login`
- `https://10.0.0.50/banking/account`
- `https://172.16.0.10/paypal/signin`

## 5. **Long Suspicious URLs**
- `https://secure-banking-update-verification-required-2024.malicious-site.com/login.php?redirect=chase.com`
- `https://urgent-account-suspended-verify-immediately.fake-domain.org/secure.html`
- `https://amazon-prime-renewal-payment-failed-update-now.suspicious.net/billing.php`

## 6. **Homograph/Punycode Attacks**
- `https://аmazon.com` (Cyrillic 'а' instead of Latin 'a')
- `https://gοοgle.com` (Greek omicron instead of Latin 'o')
- `https://microsοft.com` (Mixed character sets)

## 7. **Path-based Deception**
- `https://malicious-site.com/google.com/login`
- `https://evil-domain.org/facebook.com/signin`
- `https://phishing-site.net/paypal.com/secure`

## 8. **URL Parameter Manipulation**
- `https://fake-site.com/login?redirect=https://google.com`
- `https://malicious.org/secure.php?site=facebook.com`
- `https://phish.net/auth?target=paypal.com&return=dashboard`

## 9. **Suspicious TLDs**
- `https://google.tk` (Free TLD often used for phishing)
- `https://facebook.ml` (Mali TLD, suspicious)
- `https://amazon.ga` (Gabon TLD, unusual)
- `https://paypal.cf` (Central African Republic TLD)

## 10. **Emergency/Urgency Themes**
- `https://urgent-security-alert.com/verify-account-now`
- `https://account-suspended-action-required.net/restore`
- `https://billing-problem-update-payment.org/fix-now`
- `https://security-breach-change-password.com/secure`

## **Testing with Your System**

### High-Risk URLs (Should be detected):
1. `https://gooogle.com` - Typosquatting
2. `https://192.168.1.1/secure/banking` - IP + suspicious path
3. `https://urgent-verify-account.tk/login` - Suspicious TLD + urgency
4. `https://security.facebook-update.com/login` - Subdomain spoofing

### Medium-Risk URLs:
1. `https://bit.ly/3suspiciouslink` - URL shortener
2. `https://login-verification.com` - Generic suspicious domain
3. `https://account-update-required.org` - Urgency keywords

### Low-Risk URLs (Legitimate):
1. `https://google.com` - Real Google
2. `https://facebook.com` - Real Facebook
3. `https://amazon.com` - Real Amazon
4. `https://github.com` - Real GitHub

## **Key Indicators Your System Should Detect**

✅ **Domain typos and variations**
✅ **Suspicious character substitutions**
✅ **IP addresses instead of domains**
✅ **Unusual TLDs (.tk, .ml, .ga, .cf)**
✅ **Long URLs with multiple suspicious keywords**
✅ **Subdomain spoofing patterns**
✅ **Urgency and security-themed language**

## **Testing Commands**

You can test these URLs in your Flask app at `http://localhost:5000` or create automated tests.

Remember: These examples help improve cybersecurity by testing detection systems and educating users about phishing threats!
