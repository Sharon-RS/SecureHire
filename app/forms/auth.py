"""Authentication and profile forms."""

from email_validator import EmailNotValidError, validate_email
from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError


class LocalEmail:
    """Validate syntax offline while accepting reserved synthetic .test addresses."""

    def __call__(self, _form, field):
        try:
            validated = validate_email(
                field.data.strip(),
                check_deliverability=False,
                test_environment=True,
            )
        except EmailNotValidError as exc:
            raise ValidationError("Enter a valid email address.") from exc
        field.data = validated.normalized


class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), LocalEmail(), Length(max=255)])
    role = SelectField(
        "I am joining as",
        choices=[("buyer", "Buyer"), ("freelancer", "Freelancer")],
        validators=[DataRequired()],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=12, max=128, message="Use at least 12 characters.")],
    )
    confirm_password = PasswordField(
        "Confirm password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), LocalEmail(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Sign in")


class ProfileForm(FlaskForm):
    display_name = StringField("Display name", validators=[DataRequired(), Length(max=100)])
    bio = TextAreaField("About", validators=[Length(max=3000)])
    skills = TextAreaField("Skills", validators=[Length(max=1500)])
    submit = SubmitField("Save profile")


class LogoutForm(FlaskForm):
    submit = SubmitField("Sign out")
