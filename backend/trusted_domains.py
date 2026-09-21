TRUSTED_DOMAINS = {
    #Search Engines
    "google.com", "www.google.com",
    "bing.com", "www.bing.com",
    "yahoo.com", "www.yahoo.com",
    "duckduckgo.com", "www.duckduckgo.com",
    "baidu.com", "www.baidu.com",

    #  Google Services 
    "gmail.com", "mail.google.com",
    "drive.google.com", "docs.google.com",
    "maps.google.com", "play.google.com",
    "accounts.google.com", "calendar.google.com",
    "meet.google.com", "translate.google.com",

    #   Social Media   
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com",
    "x.com", "www.x.com",
    "linkedin.com", "www.linkedin.com",
    "reddit.com", "www.reddit.com",
    "pinterest.com", "www.pinterest.com",
    "tiktok.com", "www.tiktok.com",
    "snapchat.com", "www.snapchat.com",

    #    Video and Streaming   
    "youtube.com", "www.youtube.com",
    "netflix.com", "www.netflix.com",
    "twitch.tv", "www.twitch.tv",
    "vimeo.com", "www.vimeo.com",
    "hulu.com", "www.hulu.com",
    "disneyplus.com", "www.disneyplus.com",
    "primevideo.com", "www.primevideo.com",
    "dailymotion.com", "www.dailymotion.com",

    #  Microsoft 
    "microsoft.com", "www.microsoft.com",
    "office.com", "www.office.com",
    "outlook.com", "www.outlook.com",
    "live.com", "www.live.com",
    "azure.com", "www.azure.com",
    "onedrive.live.com", "teams.microsoft.com",
    "bing.com", "www.bing.com",

    #  Apple 
    "apple.com", "www.apple.com",
    "icloud.com", "www.icloud.com",
    "itunes.apple.com",

    #  Amazon 
    "amazon.com", "www.amazon.com",
    "aws.amazon.com", "cloudfront.net",

    #  Developer and Tech 
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "stackoverflow.com", "www.stackoverflow.com",
    "bitbucket.org", "www.bitbucket.org",
    "npmjs.com", "www.npmjs.com",
    "pypi.org", "www.pypi.org",
    "developer.mozilla.org",
    "docs.python.org",
    "reactjs.org", "www.reactjs.org",

    #  E-commerce 
    "ebay.com", "www.ebay.com",
    "etsy.com", "www.etsy.com",
    "shopify.com", "www.shopify.com",

    #  Finance — Major Global 
    "paypal.com", "www.paypal.com",
    "stripe.com", "www.stripe.com",
    "chase.com", "www.chase.com",
    "bankofamerica.com", "www.bankofamerica.com",
    "wellsfargo.com", "www.wellsfargo.com",
    "citibank.com", "www.citibank.com",
    "barclays.com", "www.barclays.com",
    "hsbc.com", "www.hsbc.com",
    "binance.com", "www.binance.com",
    "coinbase.com", "www.coinbase.com",

    #  Bangladesh-Specific 
    "bkash.com", "www.bkash.com",
    "nagad.com.bd", "www.nagad.com.bd",
    "dutchbanglabank.com", "www.dutchbanglabank.com",
    "islamibankbd.com", "www.islamibankbd.com",
    "bracbank.com", "www.bracbank.com",
    "thecitybank.com", "www.thecitybank.com",
    "ebl.com.bd", "www.ebl.com.bd",
    "ucbl.com.bd", "www.ucbl.com.bd",
    "bracu.ac.bd", "www.bracu.ac.bd",

    #  Communication 
    "slack.com", "www.slack.com",
    "discord.com", "www.discord.com",
    "zoom.us", "www.zoom.us",
    "whatsapp.com", "www.whatsapp.com",
    "telegram.org", "www.telegram.org",
    "skype.com", "www.skype.com",

    #  Cloud and Infrastructure 
    "cloudflare.com", "www.cloudflare.com",
    "digitalocean.com", "www.digitalocean.com",
    "heroku.com", "www.heroku.com",
    "vercel.com", "www.vercel.com",
    "netlify.com", "www.netlify.com",
    "supabase.com", "www.supabase.com",
    "render.com", "www.render.com",

    #  Productivity 
    "notion.so", "www.notion.so",
    "figma.com", "www.figma.com",
    "canva.com", "www.canva.com",
    "trello.com", "www.trello.com",
    "asana.com", "www.asana.com",
    "dropbox.com", "www.dropbox.com",
    "spotify.com", "www.spotify.com",

    #  News 
    "bbc.com", "www.bbc.com",
    "cnn.com", "www.cnn.com",
    "nytimes.com", "www.nytimes.com",
    "reuters.com", "www.reuters.com",
    "theguardian.com", "www.theguardian.com",

    #  Education 
    "wikipedia.org", "www.wikipedia.org",
    "en.wikipedia.org",
    "coursera.org", "www.coursera.org",
    "udemy.com", "www.udemy.com",
    "khanacademy.org", "www.khanacademy.org",
    "edx.org", "www.edx.org",

    #  Analytics 
    "semrush.com", "www.semrush.com",
    "similarweb.com", "www.similarweb.com",
    "analytics.google.com",
}


def is_trusted(hostname: str) -> bool:
    """
    Returns True if the hostname is in the trusted domain list.
    Strips www prefix for root domain matching.
    """
    if not hostname:
        return False

    hostname = hostname.lower().strip()

    if hostname in TRUSTED_DOMAINS:
        return True

    if hostname.startswith("www."):
        root = hostname[4:]
        if root in TRUSTED_DOMAINS:
            return True

    return False