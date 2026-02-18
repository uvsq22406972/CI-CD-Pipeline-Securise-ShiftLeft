"""
Page de connexion/inscription sécurisé en Flask.

Structure inspirée de (code entièrement réécrit et adapté en Python/Flask):
https://medium.com/@ajuatahcodingarena/building-a-secure-login-and-registration-system-with-html-css-javascript-php-and-mysql-591f839ee8f3

Améliorations de sécurité ajoutées:
- Protection CSRF sur les formulaires
- Hachage sur les mots de passe avec bcrypt
- Limitation du nombre de tentatives (anti brute-force)
- Entêtes HTTP de sécurité
- Validation des entrées utilisateur
- Accès au base de données sécurisé via SQLAlchemy
- RBAC: User et admin
"""

import os
import click
import re
from datetime import timedelta

from flask import Flask, render_template, redirect, url_for, flash, current_app
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask import abort
from app.setup_log import configure_logging


from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)

from werkzeug.security import generate_password_hash, check_password_hash

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_talisman import Talisman

from sqlalchemy import create_engine, String, Integer, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

from app.config import DevConfig, ProdConfig
from flask import request

#Base SQL
class Base(DeclarativeBase):
    """Classe de base SQLAlchemy."""
    pass


class User(Base, UserMixin):
    """
    Modèle utilisateur minimal: id, email unique, mot de passe haché.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")

    def is_admin(self) -> bool:
        return self.role == "admin"


def init_db(engine):
    """Création des tables si elles n'existent pas."""
    Base.metadata.create_all(engine)

#RBAC décorateur
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if not getattr(current_user, "is_admin", lambda: False)():
            abort(403)
        return view_func(*args, **kwargs)
    return wrapper

#Formulaires
class LoginForm(FlaskForm):
    """Formulaire de connexion avec validation."""
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Mot de passe", validators=[DataRequired(), Length(min=12, max=128)])


class RegisterForm(FlaskForm):
    """Formulaire d'inscription avec confirmation du mot de passe."""
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email requis."),
            Email(message="Email invalide."),
            Length(max=255, message="Email trop long.")
        ],
    )
    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(message="Mot de passe requis."),
            Length(min=12, max=128, message="Mot de passe trop court (12 caractères minimum).")
        ],
    )
    password2 = PasswordField(
        "Confirmation du mot de passe",
        validators=[
            DataRequired(message="Confirmation requise."),
            EqualTo("password", message="Les mots de passe ne correspondent pas.")
        ],
    )
    
#Créer application Flask
def create_app():
    app = Flask(__name__)
    env = os.getenv("APP_ENV", "dev").lower()
    app.config.from_object(ProdConfig if env == "prod" else DevConfig)
    configure_logging(app)
    engine = create_engine(app.config["DB_URL"], future=True)
    app.engine = engine

    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS __db_init_lock (id INTEGER PRIMARY KEY)")
    
    try:
        init_db(engine)
    except Exception as e:
        if "already exists" not in str(e).lower():
            raise
    
    csrf = CSRFProtect()
    csrf.init_app(app)

    #Durée de vie de session
    app.permanent_session_lifetime = timedelta(hours=8)

    #Ajout d'entêtes de sécurité HTTP (CSP, etc.)
    Talisman(
        app,
        content_security_policy={"default-src": ["'self'"], "style-src": ["'self'"]},
        force_https=False,
        session_cookie_secure=False,
        session_cookie_http_only=True,
        strict_transport_security=False,
    )

    #Limitation du nombre de requêtes par IP (anti brute-force)
    limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    default_limits=["200 per day", "50 per hour"],
    enabled=app.config.get("RATELIMIT_ENABLED", True),
    )


    #Gestionnaire d'authentification Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        """Charge l'utilisateur depuis la base à partir de son ID."""
        try:
            uid = int(user_id)
        except ValueError:
            return None

        with Session(current_app.engine) as s:
            return s.get(User, uid)

    #Verif mdp
    def mot_de_passe_robuste(pw: str) -> bool:
        """
        Vérifie la robustesse minimale : >= 12 caractères, minuscule, majuscule, chiffre, caractère spécial
        """
        if len(pw) < 12:
            return False

        return (
            re.search(r"[a-z]", pw)
            and re.search(r"[A-Z]", pw)
            and re.search(r"\d", pw)
            and re.search(r"[^A-Za-z0-9]", pw)
        )
    
    #Creation admin via CLI
    @app.cli.command("create-admin")
    @click.option("--email", default=None, help="Email de l'admin")
    @click.option("--password", default=None, help="Mot de passe de l'admin (sinon prompt)")
    def create_admin(email, password):
        """Créer un compte admin via CLI (provisioning/dev)."""
        #Email
        if not email:
            email = click.prompt("Email", type=str).strip().lower()

        #Password (prompt sécurisé si non fourni)
        if not password:
            password = click.prompt("Mot de passe", hide_input=True, type=str)
            password_confirm = click.prompt("Confirmez le mot de passe", hide_input=True, type=str)

            if password != password_confirm:
                raise click.ClickException("Les mots de passe ne correspondent pas.")

        #Robustesse du mot de passe
        if not mot_de_passe_robuste(password):
            raise click.ClickException(
                "Mot de passe trop faible : 12+ caractères, majuscule, minuscule, chiffre, caractère spécial."
            )

        pw_hash = generate_password_hash(password)

        with Session(current_app.engine) as s:
            existing = s.scalar(select(User).where(User.email == email))
            if existing:
                raise click.ClickException("Un utilisateur avec cet email existe déjà.")

            s.add(User(email=email, password_hash=pw_hash, role="admin"))
            s.commit()

        click.echo(f"Admin créé: {email}")
        
    #Routes web
    @app.get("/")
    def index():
        """Page d'accueil."""
        return render_template("index.html")

    #Inscription
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per hour")
    def register():
        """Création d'un nouveau compte utilisateur."""
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = RegisterForm()

        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            password = form.password.data

            #Vérification robustesse
            if not mot_de_passe_robuste(password):
                flash("Mot de passe trop faible : 12+ caractères, majuscule, minuscule, chiffre, caractère spécial.", "warning")
                return render_template("register.html", form=form)

            pw_hash = generate_password_hash(password)

            with Session(current_app.engine) as s:
                #Vérifie si email déjà existant
                if s.scalar(select(User).where(User.email == email)):
                    flash("Email déjà utilisé.", "warning")
                    return render_template("register.html", form=form)

                s.add(User(email=email, password_hash=pw_hash, role="user"))
                s.commit()

            flash("Compte créé avec succès.", "success")
            return redirect(url_for("login"))
        if request.method == "POST" and not form.validate():
            flash("Formulaire invalide — corrige les champs en rouge.", "danger")
            print("ERREURS REGISTER:", form.errors)
        return render_template("register.html", form=form)

    #Connexion
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        """Connexion utilisateur sécurisée."""
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = LoginForm()

        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            password = form.password.data

            with Session(current_app.engine) as s:
                user = s.scalar(select(User).where(User.email == email))

            #Message générique pour éviter l’énumération d’utilisateurs
            if not user or not check_password_hash(user.password_hash, password):
                flash("Identifiants invalides.", "danger")
                return render_template("login.html", form=form)

            login_user(user)
            flash("Connexion réussie.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html", form=form)

    #Dashboard protégé
    @app.get("/dashboard")
    @login_required
    def dashboard():
        """Page protégée accessible uniquement après authentification."""
        return render_template("dashboard.html", email=current_user.email, role=current_user.role)
    
    @app.get("/admin")
    @admin_required
    def admin():
        return render_template("admin.html", email=current_user.email, role=current_user.role)

    #Logout sécurisé (POST + CSRF)
    @app.post("/logout")
    @login_required
    def logout():
        """Déconnexion sécurisée (POST + CSRF)."""
        logout_user()
        flash("Déconnecté.", "info")
        return redirect(url_for("index"))

    return app

#Lancement direct en mode développement
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
