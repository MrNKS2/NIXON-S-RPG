from db import db
from flask_login import UserMixin

class Usuario(db.Model, UserMixin):
    __tablename__ = "usuarios"
    id = db.Column(db.Integer, primary_key=True)
    nome_usuario = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    senha = db.Column(db.String(255), nullable=False)

    personagens = db.relationship("Personagem", backref="usuario", lazy=True, cascade="all, delete-orphan")


class Personagem(db.Model):
    __tablename__ = "personagens"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)

    status = db.relationship("Status", backref="personagem", lazy=True, cascade="all, delete-orphan")
    pericias = db.relationship("Pericia", backref="personagem", lazy=True, cascade="all, delete-orphan")
    itens = db.relationship("Item", backref="personagem", lazy=True, cascade="all, delete-orphan")


class Status(db.Model):
    __tablename__ = "status"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    valor = db.Column(db.Integer, nullable=False)
    personagem_id = db.Column(db.Integer, db.ForeignKey("personagens.id"), nullable=False)


class Item(db.Model):
    __tablename__ = "itens"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    bonus = db.Column(db.Integer, default=0)
    personagem_id = db.Column(db.Integer, db.ForeignKey("personagens.id"), nullable=False)


class Pericia(db.Model):
    __tablename__ = "pericias"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    bonus_fixo = db.Column(db.Integer, default=0)
    usa_status = db.Column(db.String(120), nullable=True)
    usa_item = db.Column(db.Integer, db.ForeignKey("itens.id"), nullable=True) 
    dado_padrao = db.Column(db.String(10), nullable=True) 
    personagem_id = db.Column(db.Integer, db.ForeignKey("personagens.id"), nullable=False)
