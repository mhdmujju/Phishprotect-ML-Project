#!/usr/bin/env python3
# generate_phishing_dataset.py
# Creates a 200,000-row URL dataset (142,857 legitimate, 57,143 phishing) and zips it.
# Usage: python3 generate_phishing_dataset.py

import random, zipfile, pathlib, sys
import pandas as pd

random.seed(42)

LEGITIMATE_COUNT = 142_857
PHISHING_COUNT = 57_143

well_known_domains = [
    "google.com","youtube.com","facebook.com","instagram.com","twitter.com","wikipedia.org","amazon.com","linkedin.com",
    "yahoo.com","bing.com","reddit.com","netflix.com","microsoft.com","apple.com","ebay.com","whatsapp.com","tiktok.com",
    "pinterest.com","paypal.com","dropbox.com","wordpress.com","github.com","stackoverflow.com","medium.com","bbc.co.uk",
    "nytimes.com","cnn.com","spotify.com","hulu.com","etsy.com","adobe.com","imdb.com","tripadvisor.com","uber.com",
    "airbnb.com","booking.com","guardian.co.uk","theverge.com","wired.com","salesforce.com","slack.com","zoom.us","quora.com",
    "soundcloud.com","behance.net","discord.com","tumblr.com","flickr.com","oracle.com","intel.com","chase.com","bankofamerica.com",
    "wellsfargo.com","mozilla.org","ikea.com","target.com","bestbuy.com","costco.com","foxnews.com","forbes.com","bloomberg.com",
    "aliexpress.com","t-mobile.com","verizon.com","att.com","twitch.tv","stackexchange.com","nih.gov","who.int","nasa.gov",
    "usps.com","fedex.com","dhl.com","ups.com","indeed.com","glassdoor.com","craigslist.org","roku.com","play.google.com",
    "apps.apple.com","developer.android.com","developer.apple.com","gov.uk","irs.gov","bbc.com","nationalgeographic.com",
    "espn.com","kayak.com","mint.com","stripe.com","squareup.com","venmo.com","zillow.com","realtor.com","redfin.com","mlb.com",
    "nba.com","nfl.com","nhl.com","espncricinfo.com","britannica.com","dictionary.com","scribd.com","archive.org","mayoclinic.org",
    "healthline.com","webmd.com","khanacademy.org","coursera.org","edx.org","udemy.com","leetcode.com","kaggle.com","arxiv.org",
    "nature.com","sciencedirect.com","sciencemag.org","pubmed.ncbi.nlm.nih.gov","nejm.org","springer.com","techcrunch.com",
    "mashable.com","engadget.com","cnet.com","pcmag.com","tomshardware.com","xda-developers.com","androidauthority.com","9to5mac.com",
    "macrumors.com","appleinsider.com","superuser.com","dev.to","gimp.org","blender.org","unity.com","unrealengine.com","steamcommunity.com",
    "store.steampowered.com","epicgames.com","gog.com","nintendo.com","playstation.com","xbox.com","ea.com","ubisoft.com","riotgames.com",
    "duckduckgo.com","protonmail.com","zoho.com","fastmail.com","mailchimp.com","hubspot.com","yandex.ru","baidu.com","weibo.com",
    "qq.com","alibaba.com","taobao.com","jd.com","shopify.com","magento.com","woocommerce.com","cloudflare.com","digitalocean.com",
    "heroku.com","aws.amazon.com","azure.microsoft.com","googleapis.com","firebase.google.com","vercel.com","netlify.com",
    "godaddy.com","namecheap.com","bluehost.com","hostgator.com","ovh.com","linode.com","stanford.edu","mit.edu","harvard.edu",
    "ox.ac.uk","cam.ac.uk","utoronto.ca","ucla.edu","berkeley.edu","columbia.edu","princeton.edu","yale.edu","notion.so",
    "trello.com","asana.com","office.com","outlook.com","live.com","yelp.com","opentable.com","grubhub.com","doordash.com",
    "seamless.com","mapquest.com","maps.google.com","weather.com","accuweather.com","smithsonianmag.com","nationalparks.org",
    "time.com","patreon.com","kickstarter.com","indiegogo.com","gofundme.com","canva.com","dribbble.com","codecademy.com",
    "geeksforgeeks.org","hackerrank.com"
]

path_samples = [
    "/", "/home", "/about", "/contact", "/login", "/signin", "/dashboard", "/products", "/shop", "/search",
    "/news", "/blog", "/help", "/faq", "/support", "/account", "/profile", "/settings", "/terms", "/privacy",
    "/careers", "/signup", "/register", "/offers", "/deals", "/category/electronics", "/category/books",
    "/category/fashion", "/p/12345", "/item/67890", "/orders", "/cart", "/checkout", "/subscribe", "/unsubscribe",
    "/sitemap.xml", "/robots.txt", "/security", "/payments", "/billing", "/profile/settings", "/user/profile"
]
subdomains = ["www", "m", "secure", "app", "blog", "shop", "help", "support", "portal", "news", "api", "docs", "developer", "en", "uk"]

# Build legitimate URLs
legit_urls = []
must_include = ["google.com","youtube.com","facebook.com","amazon.com","twitter.com","instagram.com","microsoft.com","apple.com","github.com","wikipedia.org"]
for domain in must_include:
    for i in range(25):
        sd = random.choice(subdomains + [""])
        path = random.choice(path_samples)
        prefix = f"{sd}." if sd else ""
        url = f"https://{prefix}{domain}{path}"
        if random.random() < 0.01:
            url = url.replace("https://", "http://")
        legit_urls.append(url)

remaining = LEGITIMATE_COUNT - len(legit_urls)
domains_len = len(well_known_domains)
paths_len = len(path_samples)
sub_len = len(subdomains)

for i in range(remaining):
    domain = well_known_domains[(i * 17) % domains_len]
    sd = subdomains[(i * 5) % sub_len] if (i % 3 == 0) else ""
    path = path_samples[(i * 13) % paths_len]
    if i % 11 == 0:
        path = f"{path.rstrip('/')}/id{i}"
    prefix = f"{sd}." if sd else ""
    url = f"https://{prefix}{domain}{path}"
    if (i % 197) == 0:
        url = url.replace("https://", "http://")
    legit_urls.append(url)

# Build phishing URLs
brands = [
    "paypal","bank","amazon","google","facebook","apple","microsoft","netflix","ebay","gmail","amazon-pay","chase",
    "wellsfargo","paypal-secure","verizon","att","instagram","linkedin","twitter","github","appleid","spotify","uber",
    "airbnb","booking","paypallogin","securepay","bankofamerica","citibank","hsbc","barclays","paypalverify","paypal-auth"
]
tlds = [".com", ".net", ".org", ".info", ".biz", ".co", ".xyz", ".top", ".online", ".site"]
patterns = [
    "secure-{brand}-login{num}{tld}",
    "{brand}-account-update{num}{tld}",
    "verify-{brand}{num}{tld}",
    "{brand}.secure-login{num}{tld}",
    "{brand}-auth{num}{tld}",
    "{brand}login{num}{tld}",
    "{brand}-support{num}{tld}",
    "update-{brand}-payment{num}{tld}",
    "{brand}-{num}{tld}",
    "{brand}--login{num}{tld}",
    "{brand}login-secure{num}{tld}",
    "{brand}{num}-secure{tld}"
]

phish_urls = []
for i in range(PHISHING_COUNT):
    brand = brands[i % len(brands)]
    tld = tlds[i % len(tlds)]
    pattern = patterns[i % len(patterns)]
    num = 500_000 + i
    domain = pattern.format(brand=brand, num=num, tld=tld)
    if i % 3 != 0:
        path = f"/login.php?user={1000 + (i % 9000)}&session={500000 + i}"
        url = f"http://{domain}{path}"
    else:
        url = f"http://{domain}/"
    phish_urls.append(url)

# Combine, shuffle and save
rows = [(u, "legitimate") for u in legit_urls[:LEGITIMATE_COUNT]] + [(u, "phishing") for u in phish_urls[:PHISHING_COUNT]]
df = pd.DataFrame(rows, columns=["URL", "Label"])
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

csv_path = pathlib.Path("phishing_dataset_200000.csv")
zip_path = pathlib.Path("phishing_dataset_200000.zip")

print("Saving CSV (this may take 20-60 seconds depending on your machine)...")
df.to_csv(csv_path, index=False)

print("Creating ZIP...")
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.write(csv_path, arcname=csv_path.name)

print(f"Done. Files created:\n  {csv_path.resolve()}\n  {zip_path.resolve()}")
print("Row counts:", len(df), df['Label'].value_counts().to_dict())
