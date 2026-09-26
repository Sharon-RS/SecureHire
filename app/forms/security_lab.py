"""CSRF-protected administration forms for the Security Lab framework."""

from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired


class SecurityModeForm(FlaskForm):
    mode = SelectField(
        "Stored mode",
        choices=[("mitigated", "Mitigated"), ("vulnerable", "Vulnerable")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Save mode")
