
import yaml
from typing import Optional

from sqlalchemy import Column, Integer, String, Boolean

from db_cli import Base


class MailPolicyError(Exception):
    def __init__(self, msg: Optional[str] = "something was wrong"):
        super().__init__(f"mail error: {msg}")


class MailFilterModel(Base):
    __tablename__ = 'mail_domain_filter'

    id = Column(Integer, primary_key=True)
    mail_domain = Column(String(100), unique=True, nullable=False)
    blacklisted = Column(Boolean, nullable=False, default=False)
    whitelisted = Column(Boolean, nullable=False, default=False)



class MailFilter:

    def __init__(self):
        self._need_mail_domain_filter = None
        self._mail_domain_whitelisted = None
        self._mail_domain_blacklisted = None

        self.update_policy()

    def update_policy(self):
        with open("mail_policy.yaml", 'r') as _f:
            _config = yaml.safe_load(_f)
        self._need_mail_domain_filter = _config['need_mail_domain_filter']
        self._mail_domain_whitelisted = _config['mail_domain_whitelisted']
        self._mail_domain_blacklisted = _config['mail_domain_blacklisted']

    def get_policy(self):
        return {
                "need_mail_domain_filter": self._need_mail_domain_filter,
                "_mail_domain_whitelisted": self._mail_domain_whitelisted,
                "_mail_domain_blacklisted": self._mail_domain_blacklisted
            }

    def check_domain_allowed(self, session, email: str) -> bool:
        if not self._need_mail_domain_filter:
            return True

        domain = email.split('@')[1]
        """
        !!! FIRST CREATE DB TABLE
        """
        checked_domain = session.query(MailFilterModel).filter_by(mail_domain=domain).first()

        if self._mail_domain_whitelisted and not checked_domain:
            raise MailPolicyError(" mail domain not whitelisted")

        if self._mail_domain_whitelisted and not checked_domain.whitelisted:
            raise MailPolicyError(" mail domain not whitelisted")

        if self._mail_domain_blacklisted and checked_domain.blacklisted:
            raise MailPolicyError(" mail domain blacklisted")

        return True
