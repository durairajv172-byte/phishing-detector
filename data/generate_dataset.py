"""
Generates a synthetic labeled dataset of phishing and legitimate emails.
Output: data/emails.csv with columns [text, label] where label is 1=phishing, 0=safe.
"""
import csv
import random

random.seed(42)

BRANDS = ["PayPal", "Amazon", "Netflix", "Microsoft 365", "Apple ID", "Bank of America",
          "Chase Bank", "DHL", "FedEx", "LinkedIn", "Instagram", "Google", "HDFC Bank",
          "SBI Bank", "Steam", "Facebook"]

URGENT_PHRASES = [
    "Your account has been suspended", "Immediate action required",
    "Unusual sign-in activity detected", "Your payment could not be processed",
    "Your account will be permanently closed within 24 hours",
    "We noticed a login from a new device", "Your subscription has expired",
    "Security alert: verify your identity now", "You have won a prize",
    "Your parcel could not be delivered", "Your password will expire today",
]

PHISH_URLS = [
    "http://secure-{brand}-verify.com/login",
    "http://{brand}.account-update.info/confirm",
    "http://bit.ly/3xJ{n}kQ",
    "http://{brand}-support.security-check.net",
    "http://192.168.44.12/{brand}/reset",
    "http://{brand}.com-verify-account.ru/signin",
]

PHISH_CLOSERS = [
    "Click the link below within 24 hours or your account will be locked permanently.",
    "Failure to verify will result in permanent suspension of your account.",
    "Please confirm your password and card details immediately to avoid closure.",
    "Verify now to claim your reward before it expires.",
    "Update your billing information now to avoid service interruption.",
    "Enter your login credentials to restore full access.",
]

def phishing_email(i):
    brand = random.choice(BRANDS)
    urgent = random.choice(URGENT_PHRASES)
    url = random.choice(PHISH_URLS).format(brand=brand.lower().replace(" ", ""), n=random.randint(10, 99))
    closer = random.choice(PHISH_CLOSERS)
    greeting = random.choice(["Dear Customer,", "Dear Valued User,", "Hello,", "Attention:"])
    body = (
        f"{greeting}\n\n{urgent} on your {brand} account. {closer}\n\n"
        f"Click here to verify: {url}\n\n"
        f"Please act now to prevent unauthorized access to your account. "
        f"This is an automated security message from the {brand} team.\n\n"
        f"If you do not respond within 24 hours your account access will be revoked."
    )
    return body

LEGIT_SENDERS = ["your manager", "a colleague", "your university", "a friend", "your bank (statement)",
                  "a newsletter", "a delivery service", "an online store receipt", "a meeting organizer"]

LEGIT_TEMPLATES = [
    "Hi {name},\n\nJust a reminder that our team meeting is scheduled for {day} at {time}. "
    "Please review the attached agenda before then and let me know if you have questions.\n\nThanks,\n{sender}",

    "Hello {name},\n\nYour order #{orderid} has shipped and is expected to arrive by {day}. "
    "You can track it using the courier's official tracking page linked in your account order history.\n\nThank you for shopping with us.",

    "Hi {name},\n\nAttaching the notes from today's class on {topic}. Assignment 3 is due next {day}. "
    "Reach out during office hours if you need help.\n\nBest,\n{sender}",

    "Hey {name},\n\nHappy birthday! Hope you have a great day. Let's catch up for coffee sometime this {day}.\n\nCheers,\n{sender}",

    "Dear {name},\n\nThis is your monthly account statement summary. Your balance and recent transactions "
    "are available when you log in directly through the official banking app as usual. No action is required.\n\nRegards,\n{sender}",

    "Hi {name},\n\nThanks for signing up for our newsletter. Here are this week's top articles on {topic}. "
    "You can manage your subscription preferences anytime from your account settings.\n\nBest,\nThe Editorial Team",

    "Hi {name},\n\nHere's the invoice for your recent purchase, receipt #{orderid}. "
    "If you have any questions about the charge, reply to this email or contact support through the app.\n\nThanks,\n{sender}",

    "Hi {name},\n\nCongrats on finishing the project milestone! Let's sync up {day} to plan next steps. "
    "I've shared the doc in our shared drive.\n\nBest,\n{sender}",
]

NAMES = ["Alex", "Priya", "Sam", "Divya", "Arjun", "Meera", "Ravi", "Sneha", "Karthik", "Anjali"]
TOPICS = ["network security", "data structures", "machine learning", "operating systems", "databases"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

def legit_email(i):
    name = random.choice(NAMES)
    sender = random.choice(NAMES)
    day = random.choice(DAYS)
    time = random.choice(["10:00 AM", "2:30 PM", "11:00 AM", "4:00 PM"])
    orderid = random.randint(100000, 999999)
    topic = random.choice(TOPICS)
    template = random.choice(LEGIT_TEMPLATES)
    return template.format(name=name, sender=sender, day=day, time=time, orderid=orderid, topic=topic)

def main():
    rows = []
    n_each = 180
    for i in range(n_each):
        rows.append((phishing_email(i), 1))
    for i in range(n_each):
        rows.append((legit_email(i), 0))
    random.shuffle(rows)

    with open("/home/claude/phishing-detector/data/emails.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    print(f"Generated {len(rows)} emails ({n_each} phishing, {n_each} legit).")

if __name__ == "__main__":
    main()
