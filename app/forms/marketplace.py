"""Marketplace forms."""

from decimal import Decimal

from flask_wtf import FlaskForm
from wtforms import DecimalField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange


class GigForm(FlaskForm):
    title = StringField("Gig title", validators=[DataRequired(), Length(min=5, max=140)])
    category = StringField("Category", validators=[DataRequired(), Length(min=2, max=80)])
    description = TextAreaField(
        "Project description", validators=[DataRequired(), Length(min=20, max=10000)]
    )
    budget = DecimalField(
        "Budget (USD)",
        places=2,
        validators=[DataRequired(), NumberRange(min=Decimal("0.01"), max=Decimal("99999999.99"))],
    )
    submit = SubmitField("Publish gig")


class ProposalForm(FlaskForm):
    cover_letter = TextAreaField(
        "Cover letter", validators=[DataRequired(), Length(min=20, max=5000)]
    )
    proposed_price = DecimalField(
        "Your proposed price (USD)",
        places=2,
        validators=[DataRequired(), NumberRange(min=Decimal("0.01"), max=Decimal("99999999.99"))],
    )
    timeline = StringField("Estimated timeline", validators=[DataRequired(), Length(min=2, max=120)])
    submit = SubmitField("Send proposal")


class ProposalDecisionForm(FlaskForm):
    decision = SelectField(
        "Decision",
        choices=[("accepted", "Accept proposal"), ("rejected", "Decline proposal")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Save decision")


class CloseGigForm(FlaskForm):
    submit = SubmitField("Close gig")


class ReviewForm(FlaskForm):
    rating = SelectField(
        "Rating",
        choices=[(str(value), f"{value} out of 5 stars") for value in range(1, 6)],
        coerce=int,
        validators=[DataRequired(), NumberRange(min=1, max=5)],
    )
    body = TextAreaField(
        "Your review",
        validators=[DataRequired(), Length(min=3, max=1200)],
        render_kw={"rows": 5, "maxlength": 1200},
    )
    submit = SubmitField("Publish review")
