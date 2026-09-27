"""CSRF-protected Security Lab forms."""

import re

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

from ..services.demos.sqli import SAFE_SQLI_PAYLOAD


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
