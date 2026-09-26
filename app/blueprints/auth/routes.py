"""Account access and self-service profile routes."""

from flask import abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ...extensions import db
from ...forms.auth import LoginForm, LogoutForm, ProfileForm, RegistrationForm
from ...models import User
from ...repositories.users import find_user_by_email
from ...services.auth import AccountExistsError, register_user
from . import bp


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            register_user(form.email.data, form.password.data, form.role.data)
        except AccountExistsError:
            form.email.errors.append("An account with this email already exists.")
        else:
            flash("Your account is ready. Sign in to continue.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = find_user_by_email(form.email.data)
        if user and user.status == "active" and user.check_password(form.password.data):
            login_user(user, remember=False, fresh=True)
            from flask import session

            session.permanent = True
            flash("Welcome back.", "success")
            return redirect(url_for("main.dashboard"))
        flash("Email or password was not recognized.", "danger")
    return render_template("auth/login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        logout_user()
        flash("You have signed out.", "info")
        return redirect(url_for("main.index"))
    flash("Please submit the sign-out form again.", "warning")
    return redirect(url_for("main.dashboard"))


@bp.get("/profile")
@login_required
def profile():
    return render_template("auth/profile.html", profile=current_user.profile)


@bp.get("/profiles/<int:user_id>")
def public_profile(user_id: int):
    user = db.session.get(User, user_id)
    if not user or not user.profile or user.status != "active":
        abort(404)
    return render_template("auth/public_profile.html", profile=user.profile)


@bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    profile = current_user.profile
    form = ProfileForm(obj=profile)
    if form.validate_on_submit():
        profile.display_name = form.display_name.data.strip()
        profile.bio = form.bio.data.strip()
        profile.skills = form.skills.data.strip()
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("auth/profile_edit.html", form=form)
