
{
    "name": "Email Phishing Detector",
    "version": "19.0.1.0.0",
    "summary": "Phat hien email spam va phishing bang AI",
    "description": """
        Module nghien cuu phat hien email dang ngo
        bang Machine Learning.
    """,
    "category": "Tools",
    "author": "Email AI Research Team",
    "license": "LGPL-3",
    "depends": ["base", "mail"],
    "data": [
        "security/ir.model.access.csv",
        "data/cron_imap_fetch.xml",
        "views/email_record_views.xml",
        "views/imap_config_views.xml",
    ],
    "installable": True,
    "application": True,
}
