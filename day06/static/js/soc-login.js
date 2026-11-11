
"use strict";

const form = document.getElementById("loginForm");
const message = document.getElementById("message");
const button = document.getElementById("loginButton");

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    button.disabled = true;
    message.textContent = "";

    try {
        const response = await fetch(
            "/api/soc-auth/login",
            {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username: document.getElementById(
                        "username"
                    ).value,
                    password: document.getElementById(
                        "password"
                    ).value
                })
            }
        );

        if (response.ok) {
            document.getElementById(
                "password"
            ).value = "";

            window.location.assign("/");
            return;
        }

        message.textContent =
            response.status === 429
                ? "Too many attempts. Try again later."
                : "Invalid username or password.";
    } catch (error) {
        message.textContent =
            "Authentication service unavailable.";
    } finally {
        button.disabled = false;
    }
});
