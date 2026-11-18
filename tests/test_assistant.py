"""Mail assistant: inbox categories and summaries (no AI service)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoltis.mail import assistant as A  # noqa: E402


def test_categories_from_headers():
    c = A.classify
    assert c({"from": "news@shop.example", "subject": "50% off everything", "list-unsubscribe": "<mailto:u@x>"}) == "promotions"
    assert c({"from": "news@techweekly.com", "subject": "This week in open source"}) == "promotions"
    assert c({"from": "hello@brand.example", "subject": "Our new collection", "list-unsubscribe": "<https://x/u>",
              "feedback-id": "1:2:mailchimp"}) == "promotions"
    assert c({"from": "no-reply@amazon.com", "subject": "Your order has shipped"}) == "updates"
    assert c({"from": "noreply@github.com", "subject": "[zoltis] Pull request #42 merged"}) == "updates"
    assert c({"from": "billing@vendor.example", "subject": "Your invoice for November", "list-unsubscribe": "<x>"}) == "updates"
    assert c({"from": "notification@facebookmail.com", "subject": "New friend suggestions"}) == "social"
    assert c({"from": "messages-noreply@linkedin.com", "subject": "You appeared in 9 searches"}) == "social"
    assert c({"from": "dev@lists.example.org", "subject": "Re: patch", "list-id": "<dev.lists>", "list-post": "<mailto:dev@>"}) == "forums"
    assert c({"from": "someone@googlegroups.com", "subject": "Digest"}) == "forums"
    assert c({"from": "john@acme.com", "subject": "Lunch tomorrow?"}) == "primary"
    # people you've written to always stay in Primary, and the user's own choice wins
    assert c({"from": "news@shop.example", "subject": "Big sale", "list-unsubscribe": "x"}, known_contact=True) == "primary"
    assert c({"from": "john@acme.com", "subject": "Hi"}, override="updates") == "updates"


def test_summary_sentences_and_facts():
    text = """Hi team,

Please review the attached Q3 budget proposal before our meeting on Thursday, 21 November at 10:30 am. The total
comes to $48,500, which is 12% above last quarter because of the new hires.

Can you confirm by Wednesday whether marketing needs the extra $5,000? I also need sign-off from finance
before the board review.

Your order #PO-88231 should arrive next Monday. Your verification code is 482913.

Thanks,
Sara

On Mon, 18 Nov 2026 John wrote:
> This quoted text is old and must not be summarized: deadline Friday $999
"""
    r = A.summarize(text, "Q3 budget proposal", [{"filename": "budget.xlsx"}, {"filename": "logo.png", "inline": True}])
    assert r["summary"] and "budget proposal" in r["summary"][0]
    assert r["questions"] == ["Can you confirm by Wednesday whether marketing needs the extra $5,000?"]
    facts = {(f["type"], f["text"]) for f in r["facts"]}
    assert ("amount", "$48,500") in facts and ("amount", "$5,000") in facts and ("amount", "$999") not in facts
    assert ("deadline", "by Wednesday") in facts and ("time", "10:30 am") in facts
    assert ("code", "482913") in facts and ("reference", "PO-88231") in facts
    assert any(t == "date" and "21 November" in v for t, v in facts)
    assert r["action_needed"] and r["attachments"] == ["budget.xlsx"]


def test_short_or_empty_messages():
    r = A.summarize("Thanks!", "Re: hi")
    assert r["summary"] == [] and r["facts"] == [] and not r["questions"]
    assert A.summarize("", "")["words"] == 0
    long = " ".join(f"Sentence number {i} talks about the quarterly logistics plan and the warehouse." for i in range(60))
    assert 1 <= len(A.summarize(long, "logistics plan")["summary"]) <= 3
