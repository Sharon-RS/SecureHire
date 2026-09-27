"""CSRF-protected Security Lab forms."""

import re

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError

from ..services.demos.sqli import SAFE_SQLI_PAYLOAD
from ..services.demos.stored_xss import APPROVED_STORED_XSS_PAYLOAD


class SecurityModeForm(FlaskForm):
    mode = SelectField(
        "Stored mode",
        choices=[("mitigated", "Mitigated"), ("vulnerable", "Vulnerable")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Save mode")


def validate_sqli_demo_input(_form, field):
    """Allow ordinary fixture searches or the single harmless approved SQLi payload."""
    value = field.data or ""
    if value != SAFE_SQLI_PAYLOAD and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 -]{0,79}", value) is None:
        raise ValidationError(
            "Use a plain synthetic search term or the approved harmless demonstration input."
        )


class SQLiSearchForm(FlaskForm):
    search_term = StringField(
        "Gig title or category",
        validators=[DataRequired(), Length(max=80), validate_sqli_demo_input],
        render_kw={"maxlength": 80, "autocomplete": "off"},
    )
    submit = SubmitField("Run local search")


def validate_stored_xss_demo_value(_form, field):
    """Accept only the approved harmless local proof of concept."""
    if field.data != APPROVED_STORED_XSS_PAYLOAD:
        raise ValidationError("Use the approved harmless Stored XSS demonstration value.")


class StoredXssDemoForm(FlaskForm):
    payload = TextAreaField(
        "Demonstration input",
        validators=[DataRequired(), Length(max=200), validate_stored_xss_demo_value],
        render_kw={"rows": 3, "maxlength": 200, "spellcheck": "false"},
    )
    submit = SubmitField("Submit Demo")
