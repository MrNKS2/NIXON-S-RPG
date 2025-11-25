from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError
from db import db
from models import Usuario, Personagem, Status, Pericia, Item
import random
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "segredo_local")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

class FormRegistro(FlaskForm):
    nome_usuario = StringField("Nome de usuário", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    telefone = StringField("Telefone", validators=[DataRequired()])
    senha = PasswordField("Senha", validators=[DataRequired()])
    confirmar_senha = PasswordField("Confirmar senha", validators=[DataRequired(), EqualTo("senha")])
    enviar = SubmitField("Registrar")

    def validate_email(self, campo_email):
        if Usuario.query.filter_by(email=campo_email.data).first():
            raise ValidationError("Esse email já está registrado!")

    def validate_nome_usuario(self, campo_nome):
        if Usuario.query.filter_by(nome_usuario=campo_nome.data).first():
            raise ValidationError("Esse nome de usuário já está em uso!")


class FormLogin(FlaskForm):
    nome_usuario = StringField("Nome de usuário", validators=[DataRequired()])
    senha = PasswordField("Senha", validators=[DataRequired()])
    entrar = SubmitField("Entrar")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/fichas")
def fichas():
    return render_template("lista_fichas.html")

#Login / Registro
@app.route("/login", methods=["GET", "POST"])
def login():

    # LOGIN 
    if request.method == "POST" and "username" in request.form:

        entrada = request.form.get("username").strip()
        senha = request.form.get("password")

        usuario = Usuario.query.filter_by(nome_usuario=entrada).first()

        if usuario and bcrypt.check_password_hash(usuario.senha, senha):
            login_user(usuario)
            return redirect(url_for("inicio"))
        else:
            flash("Login incorreto!", "erro")

    # REGISTRO
    if request.method == "POST" and "new_username" in request.form:

        nome = request.form.get("new_username").strip()
        email = request.form.get("email").strip().lower()
        telefone = request.form.get("phone").strip()
        senha = request.form.get("new_password")
        confirmar = request.form.get("confirm_password")

        if senha != confirmar:
            flash("As senhas não coincidem!", "erro")
            return redirect(url_for("login"))

        if Usuario.query.filter_by(email=email).first():
            flash("Esse email já está registrado!", "erro")
            return redirect(url_for("login"))

        if Usuario.query.filter_by(nome_usuario=nome).first():
            flash("Esse usuário já existe!", "erro")
            return redirect(url_for("login"))

        senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")

        novo = Usuario(
            nome_usuario=nome,
            email=email,
            telefone=telefone,
            senha=senha_hash
        )
        db.session.add(novo)
        db.session.commit()
        flash("Conta criada com sucesso!", "sucesso")
        return redirect(url_for("login"))

    return render_template("login.html")


# Página inicial 
@app.route("/inicio")
@login_required
def inicio():
    personagens = Personagem.query.filter_by(usuario_id=current_user.id).all()
    return render_template("lista_fichas.html", nome=current_user.nome_usuario, personagens=personagens)

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# Persongem CRUD
@app.route("/novo_personagem", methods=["POST"])
@login_required
def novo_personagem():
    nome = request.form.get("nome")
    if not nome:
        flash("Nome do personagem obrigatório.", "erro")
        return redirect(url_for("inicio"))
    p = Personagem(nome=nome.strip(), usuario_id=current_user.id)
    db.session.add(p)
    db.session.commit()
    flash("Personagem criado.", "sucesso")
    return redirect(url_for("inicio"))


@app.route("/excluir_personagem/<int:personagem_id>", methods=["POST"])
@login_required
def excluir_personagem(personagem_id):
    p = Personagem.query.get_or_404(personagem_id)
    if p.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    db.session.delete(p)
    db.session.commit()
    flash("Personagem excluído.", "sucesso")
    return redirect(url_for("inicio"))

# Pagina da ficha 
@app.route("/ficha/<int:personagem_id>")
@login_required
def ficha(personagem_id):
    personagem = Personagem.query.filter_by(id=personagem_id, usuario_id=current_user.id).first_or_404()
    return render_template("fichas.html", personagem=personagem, status=personagem.status, pericias=personagem.pericias, itens=personagem.itens)

# Status CRUD
@app.route("/status_adicionar/<int:personagem_id>", methods=["POST"])
@login_required
def status_adicionar(personagem_id):
    personagem = Personagem.query.get_or_404(personagem_id)
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    nome = request.form.get("nome")
    valor = request.form.get("valor", 0)
    s = Status(nome=nome.strip(), valor=int(valor), personagem_id=personagem_id)
    db.session.add(s)
    db.session.commit()
    flash("Status adicionado.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem_id))


@app.route("/status_editar/<int:status_id>", methods=["POST"])
@login_required
def status_editar(status_id):
    s = Status.query.get_or_404(status_id)
    personagem = s.personagem
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    s.nome = request.form.get("nome").strip()
    s.valor = int(request.form.get("valor", 0))
    db.session.commit()
    flash("Status atualizado.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem.id))


@app.route("/status_excluir/<int:status_id>", methods=["POST"])
@login_required
def status_excluir(status_id):
    s = Status.query.get_or_404(status_id)
    personagem = s.personagem
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    db.session.delete(s)
    db.session.commit()
    flash("Status excluído.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem.id))

# ITEM CRUD
@app.route("/item_adicionar/<int:personagem_id>", methods=["POST"])
@login_required
def item_adicionar(personagem_id):
    personagem = Personagem.query.get_or_404(personagem_id)
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    nome = request.form.get("nome")
    bonus = int(request.form.get("bonus", 0))
    it = Item(nome=nome.strip(), bonus=bonus, personagem_id=personagem_id)
    db.session.add(it)
    db.session.commit()
    flash("Item adicionado.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem_id))


@app.route("/item_editar/<int:item_id>", methods=["POST"])
@login_required
def item_editar(item_id):
    it = Item.query.get_or_404(item_id)
    personagem = it.personagem
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    it.nome = request.form.get("nome").strip()
    it.bonus = int(request.form.get("bonus", 0))
    db.session.commit()
    flash("Item atualizado.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem.id))


@app.route("/item_excluir/<int:item_id>", methods=["POST"])
@login_required
def item_excluir(item_id):
    it = Item.query.get_or_404(item_id)
    personagem = it.personagem
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    db.session.delete(it)
    db.session.commit()
    flash("Item excluído.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem.id))

# PERÍCIA CRUD

@app.route("/pericia_adicionar/<int:personagem_id>", methods=["POST"])
@login_required
def pericia_adicionar(personagem_id):
    personagem = Personagem.query.get_or_404(personagem_id)
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    nome = request.form.get("nome")
    bonus_fixo = int(request.form.get("bonus_fixo", 0))
    usa_status = request.form.get("usa_status") or None
    usa_item = request.form.get("usa_item") or None
    dado_padrao = request.form.get("dado_padrao") or None
    nova = Pericia(
        nome=nome.strip(),
        bonus_fixo=bonus_fixo,
        usa_status=usa_status,
        usa_item=int(usa_item) if usa_item else None,
        dado_padrao=dado_padrao,
        personagem_id=personagem_id
    )
    db.session.add(nova)
    db.session.commit()
    flash("Perícia adicionada.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem_id))


@app.route("/pericia_editar/<int:pericia_id>", methods=["POST"])
@login_required
def pericia_editar(pericia_id):
    p = Pericia.query.get_or_404(pericia_id)
    personagem = p.personagem
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    p.nome = request.form.get("nome").strip()
    p.bonus_fixo = int(request.form.get("bonus_fixo", 0))
    p.usa_status = request.form.get("usa_status") or None
    p.usa_item = int(request.form.get("usa_item")) if request.form.get("usa_item") else None
    p.dado_padrao = request.form.get("dado_padrao") or None
    db.session.commit()
    flash("Perícia atualizada.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem.id))


@app.route("/pericia_excluir/<int:pericia_id>", methods=["POST"])
@login_required
def pericia_excluir(pericia_id):
    p = Pericia.query.get_or_404(pericia_id)
    personagem = p.personagem
    if personagem.usuario_id != current_user.id:
        flash("Acesso negado.", "erro")
        return redirect(url_for("inicio"))
    db.session.delete(p)
    db.session.commit()
    flash("Perícia excluída.", "sucesso")
    return redirect(url_for("ficha", personagem_id=personagem.id))



# ROLAGENS

def parse_dado(expr: str):
    """Parse simples '1d20' -> (1,20). Lança ValueError se inválido."""
    partes = expr.lower().split("d")
    if len(partes) != 2:
        raise ValueError("Formato inválido")
    qtd = int(partes[0])
    faces = int(partes[1])
    return qtd, faces


@app.route("/rolar_puro/<string:dado>")
@login_required
def rolar_puro(dado):
    try:
        qtd, faces = parse_dado(dado)
    except Exception:
        return jsonify({"erro": "dado inválido"}), 400
    rolls = [random.randint(1, faces) for _ in range(qtd)]
    return jsonify({"tipo": dado, "dado": sum(rolls), "rolagens": rolls})


@app.route("/rolar_manual/<int:personagem_id>", methods=["POST"])
@login_required
def rolar_manual(personagem_id):
    personagem = Personagem.query.get_or_404(personagem_id)
    if personagem.usuario_id != current_user.id:
        return jsonify({"erro": "Acesso negado"}), 403

    tipo = request.form.get("dado")
    try:
        qtd, faces = parse_dado(tipo)
    except Exception:
        return jsonify({"erro": "dado inválido"}), 400

    try:
        modificador_manual = int(request.form.get("modificador", 0))
    except ValueError:
        modificador_manual = 0

    mods = []
    if modificador_manual:
        mods.append(modificador_manual)

    status_id = request.form.get("status_id")
    if status_id:
        st = Status.query.get(int(status_id))
        if st and st.personagem_id == personagem.id:
            mods.append(st.valor)

    item_id = request.form.get("item_id")
    if item_id:
        it = Item.query.get(int(item_id))
        if it and it.personagem_id == personagem.id:
            mods.append(it.bonus)

    pericia_id = request.form.get("pericia_id")
    if pericia_id:
        p = Pericia.query.get(int(pericia_id))
        if p and p.personagem_id == personagem.id:
            mods.append(p.bonus_fixo)
            if p.usa_status:
                st2 = Status.query.filter_by(personagem_id=personagem.id, nome=p.usa_status).first()
                if st2:
                    mods.append(st2.valor)
            if p.usa_item:
                it2 = Item.query.get(p.usa_item)
                if it2 and it2.personagem_id == personagem.id:
                    mods.append(it2.bonus)

    # para rolagem de dados
    rolls = [random.randint(1, faces) for _ in range(qtd)]
    soma_dado = sum(rolls)
    total = soma_dado + sum(mods)
    return jsonify({"tipo": tipo, "dado": soma_dado, "modificadores": sum(mods), "total": total, "rolagens": rolls})


@app.route("/rolar_pericia/<int:pericia_id>", methods=["POST"])
@login_required
def rolar_pericia(pericia_id):
    p = Pericia.query.get_or_404(pericia_id)
    personagem = p.personagem
    if personagem.usuario_id != current_user.id:
        return jsonify({"erro": "Acesso negado"}), 403

    tipo = request.form.get("dado") or p.dado_padrao
    if not tipo:
        return jsonify({"erro": "dado não informado"}), 400

    try:
        qtd, faces = parse_dado(tipo)
    except Exception:
        return jsonify({"erro": "dado inválido"}), 400

    mods = []
    if p.bonus_fixo:
        mods.append(p.bonus_fixo)
    if p.usa_status:
        st = Status.query.filter_by(personagem_id=personagem.id, nome=p.usa_status).first()
        if st:
            mods.append(st.valor)
    if p.usa_item:
        it = Item.query.get(p.usa_item)
        if it and it.personagem_id == personagem.id:
            mods.append(it.bonus)

    rolls = [random.randint(1, faces) for _ in range(qtd)]
    soma_dado = sum(rolls)
    total = soma_dado + sum(mods)
    return jsonify({"tipo": tipo, "dado": soma_dado, "modificadores": sum(mods), "total": total, "rolagens": rolls})


# Inicialização
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()