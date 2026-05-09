const API = {
  BASE_URL: "http://127.0.0.1:8000",

  async request(method, endpoint, body = null) {
    const options = {
      method,
      headers: {
        "Content-Type": "application/json",
      },
    };

    const token = localStorage.getItem("token");
    if (token) {
      options.headers["Authorization"] = `Bearer ${token}`;
    }

    if (body !== null) {
      options.body = JSON.stringify(body);
    }

    let response;
    try {
      response = await fetch(`${this.BASE_URL}${endpoint}`, options);
    } catch (error) {
      throw {
        status: 0,
        message:
          "Network error while contacting the API. Check that the backend is running and that this page origin is allowed by CORS.",
        cause: error,
      };
    }

    // Safely parse JSON (some responses may not be JSON)
    let data = null;
    try {
      data = await response.json();
    } catch {
      data = null;
    }

    if (!response.ok) {
      // 401 = token expired or invalid — clear session and force re-login.
      if (response.status === 401) {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        window.location.replace("login.html");
        return;
      }
      throw { status: response.status, data };
    }

    return data;
  },

  register(email, username, password, fullName) {
    return this.request("POST", "/auth/register", {
      email,
      username,
      password,
      full_name: fullName,
    });
  },

  login(email, password) {
    return this.request("POST", "/auth/login", { email, password });
  },

  getHealth() {
    return this.request("GET", "/health");
  },
};
