const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const openRegister = document.getElementById("openRegister");
const openLogin = document.getElementById("openLogin");

const emailInput = document.getElementById("username");
const rememberCheck = document.getElementById("remember");

// Carregar usuário salvo
window.addEventListener("load", () => {
    const savedUser = localStorage.getItem("savedUser");
    if (savedUser) {
        emailInput.value = savedUser;
        rememberCheck.checked = true;
    }
});

// Salvar usuário ao fazer login
loginForm.addEventListener("submit", () => {
    if (rememberCheck.checked) {
        localStorage.setItem("savedUser", emailInput.value);
    } else {
        localStorage.removeItem("savedUser");
    }
});

// Abrir registro
openRegister.addEventListener("click", (e) => {
    e.preventDefault();
    loginForm.classList.add("hidden");
    registerForm.classList.remove("hidden");
});

// Voltar ao login
openLogin.addEventListener("click", (e) => {
    e.preventDefault();
    registerForm.classList.add("hidden");
    loginForm.classList.remove("hidden");
});
