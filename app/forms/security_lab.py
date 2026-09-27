"""CSRF-protected Security Lab forms."""

import re

from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError

from ..services.demos.sqli import SAFE_SQLI_PAYLOAD
from ..services.demos.stored_xss import APPROVED_STORED_XSS_PAYLOAD
from ..services.demos.reflected_xss import APPROVED_REFLECTED_XSS_PAYLOAD


class CsrfFixtureResetForm(FlaskForm):
    submit = SubmitField("Reset synthetic proposal")


class IdorBolaReadForm(FlaskForm):
    target_proposal_id = SelectField(
        "Synthetic proposal",
        coerce=int,
        validators=[DataRequired()],
    )
    submit = SubmitField("Read proposal")


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


def validate_reflected_xss_search_term(_form, field):
    """Accept plain synthetic search text or the single approved harmless payload."""
    value = field.data or ""
    if value == APPROVED_REFLECTED_XSS_PAYLOAD:
        return
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,&_-]{0,79}", value) is None:
        raise ValidationError(
            "Use ordinary synthetic search text or the approved local demonstration input."
        )


class ReflectedXssSearchForm(FlaskForm):
    search_term = StringField(
        "Search term",
        validators=[DataRequired(), Length(max=160), validate_reflected_xss_search_term],
        render_kw={"maxlength": 160, "autocomplete": "off"},
    )
    submit = SubmitField("Run Demo")


class FileUploadDemoForm(FlaskForm):
    sample_case = SelectField(
        "Demonstration sample",
        choices=[
            ("custom", "Upload custom file (browse below)"),
            ("benign_doc", "Benign Text Document (sample_portfolio.txt)"),
            ("benign_img", "Benign Image (sample_diagram.png)"),
            ("harmless_php", "Harmless PHP Script (harmless_poc.php)"),
            ("harmless_py", "Harmless Python Script (harmless_script.py)"),
            ("disguised_ext", "Disguised Extension (shell.php.png)"),
        ],
        default="custom",
    )
    file = FileField("File")
    submit = SubmitField("Submit File")


class FileUploadResetForm(FlaskForm):
    submit = SubmitField("Clear uploaded files")

